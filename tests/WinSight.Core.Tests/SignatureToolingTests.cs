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
