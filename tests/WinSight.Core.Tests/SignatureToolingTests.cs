using System.Security.Cryptography;

using Microsoft.Win32;

using WinSight.Core;

using Xunit;

namespace WinSight.Core.Tests;

public sealed class SignaturePathGuardTests
{
    [Fact]
    public void AnOrdinaryLocalFileIsAccepted()
    {
        var path = Path.Combine(Path.GetTempPath(), $"winsight-guard-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(path, [1, 2, 3]);
        try
        {
            Assert.Equal(Path.GetFullPath(path), SignaturePathGuard.LocalFileArgument(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(@"\\server\share\evil.exe")]   // UNC would authenticate to a share
    [InlineData(@"\\.\C:\Windows\notepad.exe")] // Win32 device namespace
    [InlineData(@"\\?\C:\Windows\notepad.exe")] // NT device namespace
    [InlineData(@"relative\path.exe")]          // not fully qualified
    [InlineData(@"C:\this\does\not\exist.exe")] // does not exist
    public void SuspiciousOrMissingArgumentsAreRefused(string? raw)
    {
        Assert.Null(SignaturePathGuard.LocalFileArgument(raw));
    }

    [Fact]
    public void ALocalPathReportedNonLocalIsRefused()
    {
        var path = Path.Combine(Path.GetTempPath(), $"winsight-guard-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(path, [1]);
        try
        {
            Assert.Null(SignaturePathGuard.LocalFileArgument(path, _ => false));
        }
        finally
        {
            File.Delete(path);
        }
    }
}

public sealed class FileSignatureReporterTests
{
    [Fact]
    public void ItReportsTheVerdictAndTheThreeIdentificationHashes()
    {
        var bytes = new byte[] { 10, 20, 30, 40, 50 };
        var path = Path.Combine(Path.GetTempPath(), $"winsight-sig-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(path, bytes);
        try
        {
            var verdict = new SignatureVerdict(SignatureState.SignedTrusted, "CN=Contoso",
                SignatureTrustAnchor.MachineRoot, RevocationStanding.NotRevoked);
            var report = new FileSignatureReporter(new StubVerifier(verdict)).Describe(path);

            Assert.NotNull(report);
            Assert.Equal(SignatureState.SignedTrusted, report!.State);
            Assert.Equal("CN=Contoso", report.Signer);
            Assert.Equal(Convert.ToHexString(SHA256.HashData(bytes)), report.Sha256);
            // SHA-1/MD5 here only recompute the identification hashes the report exposes.
#pragma warning disable CA5350
            Assert.Equal(Convert.ToHexString(SHA1.HashData(bytes)), report.Sha1);
#pragma warning restore CA5350
            Assert.False(report.RestsOnUserInstalledTrust);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ANonLocalArgumentYieldsNoReportAndTheVerifierIsNeverCalled()
    {
        var verifier = new StubVerifier(SignatureVerdict.Unsigned);

        Assert.Null(new FileSignatureReporter(verifier).Describe(@"\\server\share\x.exe"));
        Assert.Equal(0, verifier.Calls);
    }

    [Fact]
    public void ReplacementIsBlockedUntilVerdictAndHashesDescribeTheSameObject()
    {
        var original = new byte[] { 1, 2, 3, 4, 5 };
        var replacement = new byte[] { 9, 8, 7, 6, 5 };
        var path = Path.Combine(Path.GetTempPath(), $"winsight-sig-race-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(path, original);
        try
        {
            var verifier = new ReplacingVerifier(replacement);
            var report = new FileSignatureReporter(verifier).Describe(path);

            Assert.NotNull(report);
            Assert.True(verifier.ReplacementWasBlocked);
            Assert.Equal(Convert.ToHexString(SHA256.HashData(original)), report!.Sha256);
            Assert.Equal(original, File.ReadAllBytes(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void APathReplacementDuringVerificationNeverProducesAMixedReport()
    {
        var directory = Directory.CreateTempSubdirectory("winsight-report-race-").FullName;
        var path = Path.Combine(directory, "candidate.bin");
        File.WriteAllBytes(path, [1, 2, 3, 4, 5]);
        try
        {
            var verifier = new RenamingVerifier(directory);

            var report = new FileSignatureReporter(verifier).Describe(path);

            Assert.Null(report);
            Assert.Equal(
                verifier.Replaced ? new byte[] { 9, 8, 7, 6, 5 } : new byte[] { 1, 2, 3, 4, 5 },
                File.ReadAllBytes(path));
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private sealed class StubVerifier(SignatureVerdict verdict) : ISignatureVerifier
    {
        public int Calls { get; private set; }

        public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default)
        {
            Calls++;
            return verdict;
        }

        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default) =>
            paths.ToDictionary(p => p, _ => verdict, StringComparer.OrdinalIgnoreCase);
    }

    private sealed class ReplacingVerifier(byte[] replacement) : ISignatureVerifier
    {
        public bool ReplacementWasBlocked { get; private set; }

        public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default)
        {
            try
            {
                File.WriteAllBytes(path, replacement);
            }
            catch (IOException)
            {
                ReplacementWasBlocked = true;
            }
            return SignatureVerdict.Unsigned;
        }

        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths,
            CancellationToken cancellationToken = default) =>
            paths.ToDictionary(
                path => path,
                path => Verify(path, cancellationToken),
                StringComparer.OrdinalIgnoreCase);
    }

    private sealed class RenamingVerifier(string directory) : ISignatureVerifier
    {
        public bool Replaced { get; private set; }

        public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default)
        {
            File.Move(path, Path.Combine(directory, "original.bin"));
            File.WriteAllBytes(path, [9, 8, 7, 6, 5]);
            Replaced = true;
            return new SignatureVerdict(SignatureState.SignedTrusted, "CN=Wrong object");
        }

        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths,
            CancellationToken cancellationToken = default) =>
            paths.ToDictionary(
                path => path,
                path => Verify(path, cancellationToken),
                StringComparer.OrdinalIgnoreCase);
    }
}

public sealed class EmbeddedAuthenticodeHandleTests
{
    [Fact]
    public void AnEmbeddedSignerIsReadFromTheAcquiredBytesAndReportedByNativeTrust()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var candidates = new[]
        {
            Path.Combine(windows, "explorer.exe"),
            Path.Combine(windows, "regedit.exe"),
            Path.Combine(Environment.SystemDirectory, "notepad.exe"),
            Path.Combine(windows, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
        };
        string? signedPath = null;
        string? subject = null;
        foreach (var candidate in candidates)
        {
            using var lease = AutomaticFileAccess.TryAcquire(candidate);
            if (lease is null || lease.IsDirectory)
            {
                continue;
            }
            using var stream = lease.OpenRead(FileOptions.RandomAccess);
            using var certificate = AuthenticodeCertificateReader.ReadSigner(stream);
            if (certificate is null)
            {
                continue;
            }
            signedPath = candidate;
            subject = certificate.Subject;
            break;
        }

        Assert.NotNull(signedPath);
        Assert.Contains("Microsoft", subject ?? string.Empty, StringComparison.OrdinalIgnoreCase);

        var verdict = new NativeSignatureVerifier().Verify(signedPath!);

        Assert.Equal(SignatureState.SignedTrusted, verdict.State);
        Assert.Contains("Microsoft", verdict.Signer ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }
}

public sealed class SignatureContextMenuRegistrarTests : IDisposable
{
    private readonly string _classesRoot = $@"Software\WinSight.Tests\Classes\{Guid.NewGuid():N}";

    public void Dispose() =>
        Registry.CurrentUser.DeleteSubKeyTree(_classesRoot, throwOnMissingSubKey: false);

    [Fact]
    public void RegisterCreatesAVerbThatRunsThisExecutable()
    {
        var registrar = new SignatureContextMenuRegistrar(@"C:\Program Files\WinSight\winsight-dashboard.exe", _classesRoot);

        Assert.False(registrar.IsRegistered());
        registrar.Register();

        Assert.True(registrar.IsRegistered());
        using var command = Registry.CurrentUser.OpenSubKey($@"{_classesRoot}\*\shell\WinSight.Signature\command");
        var line = (string)command!.GetValue(null)!;
        Assert.Contains("--signature", line);
        Assert.Contains("winsight-dashboard.exe", line);
        Assert.Contains("\"%1\"", line);
    }

    [Fact]
    public void UnregisterRemovesTheVerbAndIsQuietWhenAbsent()
    {
        var registrar = new SignatureContextMenuRegistrar(@"C:\WinSight\winsight-dashboard.exe", _classesRoot);
        registrar.Register();
        Assert.True(registrar.IsRegistered());

        registrar.Unregister();
        Assert.False(registrar.IsRegistered());

        registrar.Unregister(); // no throw when already gone
    }

    [Fact]
    public void ADifferentExecutableIsNotSeenAsRegistered()
    {
        new SignatureContextMenuRegistrar(@"C:\WinSight\winsight-dashboard.exe", _classesRoot).Register();

        var other = new SignatureContextMenuRegistrar(@"C:\Elsewhere\winsight-dashboard.exe", _classesRoot);
        Assert.False(other.IsRegistered());
    }
}
