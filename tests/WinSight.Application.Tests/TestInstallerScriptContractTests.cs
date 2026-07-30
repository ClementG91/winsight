using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// Pins the native-architecture preflight used by the installer lifecycle gate. This is static by
/// design: executing an installer is a VM/release gate, not a portable unit-test operation.
/// </summary>
public sealed class TestInstallerScriptContractTests
{
    private static readonly string RepositoryRoot = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    [Fact]
    public void InstallerPreflightUsesOneNativeWin32ProcessorArchitecture()
    {
        var script = File.ReadAllText(Path.Combine(RepositoryRoot, "scripts", "Test-Installer.ps1"));

        Assert.Contains("Get-CimInstance -ClassName Win32_Processor", script, StringComparison.Ordinal);
        Assert.Contains("$processorArchitectures.Count -ne 1", script, StringComparison.Ordinal);
        Assert.Contains("9 { \"x64\" }", script, StringComparison.Ordinal);
        Assert.Contains("12 { \"arm64\" }", script, StringComparison.Ordinal);
        Assert.DoesNotContain("RuntimeInformation", script, StringComparison.Ordinal);
    }

    [Fact]
    public void SignedLifecycleRequiresExactPublisherAndTimestampBeforeCandidateExecution()
    {
        var script = File.ReadAllText(Path.Combine(RepositoryRoot, "scripts", "Test-Installer.ps1"));

        Assert.Contains("[switch]$RequireSigned", script, StringComparison.Ordinal);
        Assert.Contains("[string]$ExpectedPublisher", script, StringComparison.Ordinal);
        Assert.Contains("ExpectedPublisher is mandatory when -RequireSigned", script, StringComparison.Ordinal);
        Assert.Contains("Get-AuthenticodeSignature -FilePath $Path", script, StringComparison.Ordinal);
        Assert.Contains("SignatureStatus]::Valid", script, StringComparison.Ordinal);
        Assert.Contains("SignerCertificate.Subject -cne $ExpectedPublisher", script, StringComparison.Ordinal);
        Assert.Contains("TimeStamperCertificate", script, StringComparison.Ordinal);
        Assert.Contains("Assert-ExpectedAuthenticodeSignature -Path $installer", script, StringComparison.Ordinal);
        Assert.Contains("$service = Join-Path $installDirectory \"winsight-firewall-service.exe\"", script, StringComparison.Ordinal);
        Assert.Contains("Test-PeArchitecture.ps1", script, StringComparison.Ordinal);
        Assert.Contains("-Path $candidateExecutable -Architecture $Architecture", script, StringComparison.Ordinal);

        var verifyInstaller = script.IndexOf("Assert-ExpectedAuthenticodeSignature -Path $installer", StringComparison.Ordinal);
        var executeInstaller = script.IndexOf("Start-Process -FilePath $installer", StringComparison.Ordinal);
        Assert.True(verifyInstaller >= 0 && verifyInstaller < executeInstaller);
        var verifyUninstaller = script.IndexOf("Assert-ExpectedAuthenticodeSignature -Path $uninstaller", StringComparison.Ordinal);
        var executeUninstaller = script.IndexOf("Start-Process -FilePath $uninstaller", StringComparison.Ordinal);
        Assert.True(verifyUninstaller >= 0 && verifyUninstaller < executeUninstaller);
    }
}
