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

    [Fact]
    public void ExtractExecutable_SystemRootDriverPath_Resolves()
    {
        // Driver ImagePaths use NT forms Win32 can't open as-is — without normalisation
        // every Windows driver reads as "no image" and is flagged (150+ false positives).
        Assert.NotNull(CommandLine.ExtractExecutable(@"\SystemRoot\System32\drivers\ACPI.sys"));
    }

    [Fact]
    public void ExtractExecutable_RelativeSystem32DriverPath_Resolves()
    {
        Assert.NotNull(CommandLine.ExtractExecutable(@"system32\drivers\ACPI.sys"));
    }

    [Fact]
    public void ExtractExecutable_DefaultWinlogonShell_Resolves()
    {
        // explorer.exe (the default shell) lives in %windir%, not System32 — it must
        // resolve so the benign default Winlogon shell isn't flagged.
        var resolved = CommandLine.ExtractExecutable("explorer.exe");
        Assert.NotNull(resolved);
        Assert.EndsWith("explorer.exe", resolved, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(@"\SystemRoot\system32\drivers\afd.sys")]
    [InlineData(@"\??\C:\Windows\System32\drivers\afd.sys")]
    [InlineData(@"SystemRoot\system32\drivers\afd.sys")]
    public void NtPathCandidates_YieldsAWindowsRootedForm(string input)
    {
        var candidates = CommandLine.NtPathCandidates(input).ToList();
        Assert.Contains(candidates, c => c.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase)
                                         || c.Contains(@":\", StringComparison.Ordinal));
    }
}

public sealed class WinlogonTests
{
    private static readonly string[] UserinitCommand = ["userinit.exe"];
    private static readonly string[] ExplorerCommands = ["explorer.exe", "C:\\evil.exe"];

    [Fact]
    public void SplitCommands_DropsEmptiesFromTrailingComma()
    {
        Assert.Equal(UserinitCommand, WinlogonEnumerator.SplitCommands("userinit.exe,"));
    }

    [Fact]
    public void SplitCommands_SplitsAppendedPayload()
    {
        Assert.Equal(
            ExplorerCommands,
            WinlogonEnumerator.SplitCommands("explorer.exe, C:\\evil.exe"));
    }
}

public sealed class ScheduledTaskTests
{
    private static readonly string[] NotepadCommand = [@"C:\Windows\System32\notepad.exe"];

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
        Assert.Equal(NotepadCommand,
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
            // An unsigned file must never read as trusted; it is Unsigned when the
            // catalog check ran, or Unknown if that check could not complete (load).
            Assert.Contains(r[tmp].State, new[] { SignatureState.Unsigned, SignatureState.Unknown });
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

public sealed class ScreensaverEnumeratorIntegrationTests
{
    [Fact]
    public void Enumerate_DoesNotThrow_AndEntriesAreSane()
    {
        var entries = new ScreensaverEnumerator().Enumerate().ToList();
        Assert.NotNull(entries);
        Assert.All(entries, e =>
        {
            Assert.Equal(AutostartVector.Screensaver, e.Vector);
            Assert.Equal("SCRNSAVE.EXE", e.Name);
            Assert.False(string.IsNullOrEmpty(e.Command));
        });
    }
}

public sealed class SilentProcessExitEnumeratorIntegrationTests
{
    [Fact]
    public void Enumerate_DoesNotThrow_AndEntriesAreSane()
    {
        var entries = new SilentProcessExitEnumerator().Enumerate().ToList();
        Assert.NotNull(entries);
        Assert.All(entries, e =>
        {
            Assert.Equal(AutostartVector.SilentProcessExit, e.Vector);
            Assert.Contains("MonitorProcess", e.Location);
            Assert.False(string.IsNullOrEmpty(e.Command));
        });
    }
}

public sealed class ServiceEnumeratorIntegrationTests
{
    [Fact]
    public void Enumerate_SurfacesSvchostServiceDllPayloads()
    {
        var entries = new ServiceEnumerator().Enumerate().ToList();
        Assert.NotEmpty(entries); // a real Windows box always has auto-start services

        // Every Windows install runs svchost-hosted auto-start services, so the
        // ServiceDll payload entries must be present and point at DLLs.
        var dllEntries = entries.Where(e => e.Name.EndsWith("(ServiceDll)", StringComparison.Ordinal)).ToList();
        Assert.NotEmpty(dllEntries);
        Assert.All(dllEntries, e =>
        {
            Assert.Contains("ServiceDll", e.Location);
            Assert.False(string.IsNullOrEmpty(e.Command));
        });
    }
}

public sealed class PersistenceScannerIntegrationTests
{
    [Fact]
    public void Scan_ReturnsSaneAutostartEntries()
    {
        // Enumerator integration and signature integration are covered separately.
        // A stub keeps this test from catalog-verifying hundreds of machine-specific
        // service binaries and makes it stable on busy shared CI runners.
        var entries = new PersistenceScanner(verifier: new TrustedStubVerifier()).Scan();
        Assert.NotEmpty(entries); // a real Windows box always has auto-start services
        Assert.All(entries, e =>
        {
            Assert.False(string.IsNullOrEmpty(e.Name));
            Assert.False(string.IsNullOrEmpty(e.Location));
        });
    }

    private sealed class TrustedStubVerifier : ISignatureVerifier
    {
        public SignatureVerdict Verify(string path) => new(SignatureState.SignedTrusted, "CN=Test");

        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(IReadOnlyCollection<string> paths) =>
            paths.Distinct(StringComparer.OrdinalIgnoreCase).ToDictionary(
                path => path,
                _ => new SignatureVerdict(SignatureState.SignedTrusted, "CN=Test"),
                StringComparer.OrdinalIgnoreCase);
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
    public void Verify_UnsignedFile_IsNeverTrusted()
    {
        var file = Path.Combine(Path.GetTempPath(), $"ws_{Guid.NewGuid():N}.bin");
        File.WriteAllText(file, "not a signed PE");
        try
        {
            // Unsigned when the catalog check ran, Unknown if it could not (load) —
            // but never SignedTrusted. That invariant is what actually matters.
            var state = new NativeSignatureVerifier().Verify(file).State;
            Assert.Contains(state, new[] { SignatureState.Unsigned, SignatureState.Unknown });
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

    [Theory]
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true)]
    [InlineData("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", true)]
    [InlineData("abc", false)]                    // too short
    [InlineData("", false)]                       // empty
    [InlineData(null, false)]                     // null
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85z", false)] // non-hex
    [InlineData("../key?x=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b78", false)] // URL injection attempt
    public void IsSha256_ValidatesStrictly(string? value, bool expected)
    {
        Assert.Equal(expected, VirusTotalClient.IsSha256(value));
    }

    [Fact]
    public void Lookup_RejectsNonSha256_WithoutAnyNetworkCall()
    {
        // No HttpClient interaction can happen for an invalid hash — the guard
        // returns null before any request is built.
        var client = new VirusTotalClient("dummy-key");
        Assert.Null(client.Lookup("not-a-hash"));
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
    public void Verify_FileWithoutEmbeddedSignature_IsUnknown_NotUnsigned()
    {
        // The managed verifier cannot see catalog signatures, so a file with no
        // EMBEDDED signature is genuinely undetermined — it must report Unknown, not a
        // false-alarm Unsigned (the same input might be a catalog-signed system binary).
        var f = Path.Combine(Path.GetTempPath(), $"winsight_{Guid.NewGuid():N}.bin");
        File.WriteAllText(f, "not a signed PE");
        try
        {
            var v = new SignatureVerifier().Verify(f);
            Assert.Equal(SignatureState.Unknown, v.State);
        }
        finally
        {
            File.Delete(f);
        }
    }
}
