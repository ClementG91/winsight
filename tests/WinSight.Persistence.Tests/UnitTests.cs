using WinSight.Core;
using WinSight.Persistence;
using Xunit;

namespace WinSight.Persistence.Tests;

public sealed class CommandLineTests
{
    [Fact]
    public void ExtractExecutable_QuotedPathWithArgs_ReturnsExe()
    {
        var exe = Path.Combine(Path.GetTempPath(), $"winsight_{Guid.NewGuid():N}.exe");
        File.WriteAllText(exe, "stub");
        try
        {
            var cmd = $"\"{exe}\" --run /silent";
            Assert.Equal(Path.GetFullPath(exe), CommandLine.ExtractExecutable(cmd));
        }
        finally
        {
            File.Delete(exe);
        }
    }

    [Fact]
    public void ExtractExecutable_NonExistent_ReturnsNull()
    {
        Assert.Null(CommandLine.ExtractExecutable(@"C:\nope\ghost.exe --x"));
    }

    [Fact]
    public void ExtractExecutable_BareModuleName_ResolvesInSystem32()
    {
        // kernel32 -> C:\Windows\System32\kernel32.dll (uses the real System32).
        var resolved = CommandLine.ExtractExecutable("kernel32");
        Assert.NotNull(resolved);
        Assert.EndsWith("kernel32.dll", resolved, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ExtractExecutable_Empty_ReturnsNull()
    {
        Assert.Null(CommandLine.ExtractExecutable("   "));
        Assert.Null(CommandLine.ExtractExecutable(null));
    }
}

public sealed class WinlogonTests
{
    [Fact]
    public void SplitCommands_DropsEmptiesFromTrailingComma()
    {
        Assert.Equal(new[] { "userinit.exe" }, WinlogonEnumerator.SplitCommands("userinit.exe,"));
    }

    [Fact]
    public void SplitCommands_SplitsAppendedPayload()
    {
        Assert.Equal(
            new[] { "explorer.exe", "C:\\evil.exe" },
            WinlogonEnumerator.SplitCommands("explorer.exe, C:\\evil.exe"));
    }
}

public sealed class ScheduledTaskTests
{
    private const string TaskXml = """
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <Actions Context="Author">
            <Exec>
              <Command>C:\Windows\System32\notepad.exe</Command>
              <Arguments>/A</Arguments>
            </Exec>
          </Actions>
        </Task>
        """;

    [Fact]
    public void ParseTaskCommands_ExtractsExecCommand_NamespaceAgnostic()
    {
        Assert.Equal(new[] { @"C:\Windows\System32\notepad.exe" },
            ScheduledTaskEnumerator.ParseTaskCommands(TaskXml));
    }

    [Fact]
    public void ParseTaskCommands_InvalidXml_IsEmpty()
    {
        Assert.Empty(ScheduledTaskEnumerator.ParseTaskCommands("<not xml"));
    }
}

// Integration tests — run the real pipeline on the Windows CI runner (registry,
// PowerShell signature batch). They are the first proof the blind-authored code
// actually FUNCTIONS on Windows, not just compiles.
public sealed class AuthenticodeVerifierIntegrationTests
{
    private static string OsBinary => Path.Combine(Environment.SystemDirectory, "kernel32.dll");

    [Fact]
    public void Verify_CatalogSignedOsBinary_IsTrusted()
    {
        // kernel32.dll is catalog-signed — the managed check would miss it; this proves
        // the catalog-aware PowerShell path works end-to-end.
        Assert.Equal(SignatureState.SignedTrusted, new AuthenticodeVerifier().Verify(OsBinary).State);
    }

    [Fact]
    public void VerifyMany_BatchesSignedAndUnsigned()
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"ws_{Guid.NewGuid():N}.txt");
        File.WriteAllText(tmp, "not a signed PE");
        try
        {
            var r = new AuthenticodeVerifier().VerifyMany(new[] { OsBinary, tmp });
            Assert.Equal(SignatureState.SignedTrusted, r[OsBinary].State);
            Assert.Equal(SignatureState.Unsigned, r[tmp].State);
        }
        finally
        {
            File.Delete(tmp);
        }
    }
}

public sealed class WmiSubscriptionEnumeratorIntegrationTests
{
    [Fact]
    public void Enumerate_DoesNotThrow_AndEntriesAreSane()
    {
        var entries = new WmiSubscriptionEnumerator().Enumerate().ToList();
        Assert.NotNull(entries);
        Assert.All(entries, e =>
        {
            Assert.Equal(AutostartVector.WmiSubscription, e.Vector);
            Assert.False(string.IsNullOrEmpty(e.Name));
        });
    }
}

public sealed class PersistenceScannerIntegrationTests
{
    [Fact]
    public void Scan_ReturnsSaneAutostartEntries()
    {
        var entries = new PersistenceScanner().Scan();
        Assert.NotEmpty(entries); // a real Windows box always has auto-start services
        Assert.All(entries, e =>
        {
            Assert.False(string.IsNullOrEmpty(e.Name));
            Assert.False(string.IsNullOrEmpty(e.Location));
        });
    }
}

public sealed class NativeSignatureVerifierTests
{
    [Theory]
    [InlineData(0x00000000u, SignatureState.SignedTrusted)]
    [InlineData(0x80096010u, SignatureState.SignedUntrusted)] // TRUST_E_BAD_DIGEST
    [InlineData(0x800B0004u, SignatureState.SignedUntrusted)] // subject not trusted
    public void MapResult_DefiniteStates(uint hr, SignatureState expected)
    {
        Assert.Equal(expected, NativeSignatureVerifier.MapResult(hr));
    }

    [Theory]
    [InlineData(0x800B0100u)] // TRUST_E_NOSIGNATURE -> defer to catalog
    [InlineData(0x11111111u)] // unknown -> defer
    public void MapResult_DefersToCatalog(uint hr)
    {
        Assert.Null(NativeSignatureVerifier.MapResult(hr));
    }

    [Fact]
    public void Verify_CatalogSignedOsBinary_IsTrusted_ViaFallback()
    {
        // kernel32 is catalog-signed: WinVerifyTrust reports NOSIGNATURE, the catalog
        // fallback resolves it — validating the full native->catalog chain.
        var path = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
        Assert.Equal(SignatureState.SignedTrusted, new NativeSignatureVerifier().Verify(path).State);
    }

    [Fact]
    public void Verify_UnsignedFile_IsUnsigned()
    {
        var file = Path.Combine(Path.GetTempPath(), $"ws_{Guid.NewGuid():N}.bin");
        File.WriteAllText(file, "not a signed PE");
        try
        {
            Assert.Equal(SignatureState.Unsigned, new NativeSignatureVerifier().Verify(file).State);
        }
        finally
        {
            File.Delete(file);
        }
    }
}

public sealed class HashUtilTests
{
    [Fact]
    public void Sha256File_HashesContent()
    {
        var file = Path.Combine(Path.GetTempPath(), $"ws_{Guid.NewGuid():N}.txt");
        File.WriteAllText(file, "abc");
        try
        {
            Assert.Equal(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                HashUtil.Sha256File(file));
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void Sha256File_Missing_ReturnsNull()
    {
        Assert.Null(HashUtil.Sha256File(@"C:\nope\ghost.bin"));
    }
}

public sealed class VirusTotalParseTests
{
    [Fact]
    public void ParseStats_ReadsAnalysisStats()
    {
        const string json =
            """{"data":{"attributes":{"last_analysis_stats":{"malicious":3,"suspicious":1,"undetected":60,"harmless":0,"timeout":0}}}}""";
        var v = VirusTotalClient.ParseStats(json, "abcd");
        Assert.NotNull(v);
        Assert.Equal(3, v.Malicious);
        Assert.Equal(1, v.Suspicious);
        Assert.Equal(64, v.Total);
        Assert.Contains("abcd", v.Permalink);
    }

    [Fact]
    public void ParseStats_Malformed_ReturnsNull()
    {
        Assert.Null(VirusTotalClient.ParseStats("{}", "x"));
    }
}

public sealed class CachingSignatureVerifierTests
{
    private sealed class CountingVerifier : ISignatureVerifier
    {
        public int Calls;

        public SignatureVerdict Verify(string path) => VerifyMany(new[] { path })[path];

        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(IReadOnlyCollection<string> paths)
        {
            Calls += paths.Count;
            return paths.ToDictionary(p => p, _ => SignatureVerdict.Unsigned, StringComparer.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void Verify_CachesByPathAndMtime()
    {
        var file = Path.Combine(Path.GetTempPath(), $"ws_{Guid.NewGuid():N}.bin");
        File.WriteAllText(file, "x");
        try
        {
            var inner = new CountingVerifier();
            var caching = new CachingSignatureVerifier(inner);
            Assert.Equal(SignatureState.Unsigned, caching.Verify(file).State);
            Assert.Equal(SignatureState.Unsigned, caching.Verify(file).State); // cache hit
            Assert.Equal(1, inner.Calls);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void Verify_RevalidatesAfterMtimeChange()
    {
        var file = Path.Combine(Path.GetTempPath(), $"ws_{Guid.NewGuid():N}.bin");
        File.WriteAllText(file, "x");
        try
        {
            var inner = new CountingVerifier();
            var caching = new CachingSignatureVerifier(inner);
            caching.Verify(file);
            File.SetLastWriteTimeUtc(file, DateTime.UtcNow.AddMinutes(5));
            caching.Verify(file);
            Assert.Equal(2, inner.Calls); // re-verified after the file changed
        }
        finally
        {
            File.Delete(file);
        }
    }
}

public sealed class AuthenticodeMapStatusTests
{
    [Theory]
    [InlineData("Valid", SignatureState.SignedTrusted)]
    [InlineData("NotSigned", SignatureState.Unsigned)]
    [InlineData("HashMismatch", SignatureState.SignedUntrusted)] // signed then tampered
    [InlineData("NotTrusted", SignatureState.SignedUntrusted)]
    [InlineData(null, SignatureState.Unsigned)]
    public void MapStatus_MapsSignatureStatus(string? status, SignatureState expected)
    {
        Assert.Equal(expected, AuthenticodeVerifier.MapStatus(status, "CN=Acme").State);
    }

    [Fact]
    public void MapStatus_UnknownStatusWithoutSigner_IsUnsigned()
    {
        Assert.Equal(SignatureState.Unsigned, AuthenticodeVerifier.MapStatus("UnknownError", null).State);
    }

    [Fact]
    public void MapStatus_ValidCarriesSigner()
    {
        Assert.Equal("CN=Acme", AuthenticodeVerifier.MapStatus("Valid", "CN=Acme").Signer);
    }
}

public sealed class SignatureVerifierTests
{
    [Fact]
    public void Verify_MissingFile_IsMissing()
    {
        var v = new SignatureVerifier().Verify(@"C:\does\not\exist.exe");
        Assert.Equal(SignatureState.Missing, v.State);
        Assert.False(v.IsSigned);
    }

    [Fact]
    public void Verify_UnsignedFile_IsUnsigned()
    {
        var f = Path.Combine(Path.GetTempPath(), $"winsight_{Guid.NewGuid():N}.bin");
        File.WriteAllText(f, "not a signed PE");
        try
        {
            var v = new SignatureVerifier().Verify(f);
            Assert.Equal(SignatureState.Unsigned, v.State);
        }
        finally
        {
            File.Delete(f);
        }
    }
}
