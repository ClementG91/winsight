using Xunit;
using CliContract = WinSight.Application.CliContract;

namespace WinSight.Application.Tests;

/// <summary>
/// The clean-VM runbook is a release-security control. These source contracts keep the observed
/// VM corrections from drifting back into assumptions hidden in prose.
/// </summary>
public sealed class VmQualificationKitContractTests
{
    private static readonly string RepositoryRoot = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    [Fact]
    public void KitBindsNativeArchitectureArtifactPeHashesProtectedStagingAndExternalEvidence()
    {
        var kit = File.ReadAllText(Path.Combine(
            RepositoryRoot, "docs", "validation", "VM_QUALIFICATION_KIT.md"));

        Assert.Contains("Win32_Processor", kit, StringComparison.Ordinal);
        Assert.Contains("winsight-win-$NativeArchitecture", kit, StringComparison.Ordinal);
        Assert.Contains("release-$NativeArchitecture", kit, StringComparison.Ordinal);
        Assert.Contains("-ArtifactKind $ArtifactKind", kit, StringComparison.Ordinal);
        Assert.Contains("$ExpectedInstallerSha256", kit, StringComparison.Ordinal);
        Assert.Contains("$ProtectedArtifactRoot", kit, StringComparison.Ordinal);
        Assert.Contains("$ProtectedPayloadRoot", kit, StringComparison.Ordinal);
        Assert.Contains("Test-PeArchitecture.ps1", kit, StringComparison.Ordinal);
        Assert.Contains("$CandidateExecutables = @($Cli, $Dashboard, $Service)", kit, StringComparison.Ordinal);
        Assert.Contains("Assert-CandidateFiles", kit, StringComparison.Ordinal);
        Assert.Contains("EvidenceStorageOutsideSnapshot", kit, StringComparison.Ordinal);
        Assert.Contains("protected-candidate.sha256", kit, StringComparison.Ordinal);
    }

    [Fact]
    public void KitUsesTheExactEtwModuleAndProvidesFinalAuditOnlyIpcLifecycle()
    {
        var kit = File.ReadAllText(Path.Combine(
            RepositoryRoot, "docs", "validation", "VM_QUALIFICATION_KIT.md"));

        Assert.Contains("WinSightEtwValidation.psm1", kit, StringComparison.Ordinal);
        Assert.Contains("Get-WinSightEtwSessionNames", kit, StringComparison.Ordinal);
        Assert.Contains("Assert-WinSightEtwSessionsAbsent", kit, StringComparison.Ordinal);
        Assert.DoesNotContain("Get-WinSightEtwInventory", kit, StringComparison.Ordinal);
        Assert.Contains("& $Service install", kit, StringComparison.Ordinal);
        Assert.Contains("$NativeSystemDirectory = [Environment]::SystemDirectory", kit, StringComparison.Ordinal);
        Assert.Contains("$ScExe = Join-Path $NativeSystemDirectory 'sc.exe'", kit, StringComparison.Ordinal);
        Assert.Contains("& $ScExe start WinSightFirewall", kit, StringComparison.Ordinal);
        Assert.Contains("$GitExe = Join-Path $ProgramFilesRoot 'Git\\cmd\\git.exe'", kit, StringComparison.Ordinal);
        Assert.Contains("$GhExe = Join-Path $ProgramFilesRoot 'GitHub CLI\\gh.exe'", kit, StringComparison.Ordinal);
        Assert.Contains("$NativePowerShellExe", kit, StringComparison.Ordinal);
        Assert.DoesNotContain("$env:SystemRoot", kit, StringComparison.Ordinal);
        Assert.Contains("Test-IpcBoundary.ps1", kit, StringComparison.Ordinal);
        Assert.Contains("Test-IpcNetworkObserver.ps1", kit, StringComparison.Ordinal);
        Assert.Contains("& $Service uninstall", kit, StringComparison.Ordinal);
        Assert.Contains("SCM 1060", kit, StringComparison.Ordinal);
        Assert.Contains("$installerArguments = @(", kit, StringComparison.Ordinal);
        Assert.Contains("$installerArguments += '-RequireSigned'", kit, StringComparison.Ordinal);
        Assert.DoesNotContain("$installerParams = @{", kit, StringComparison.Ordinal);
    }

    [Fact]
    public void IpcProbeUsesPortableProtectedPathsAndHasAFailClosedNetworkLogonMode()
    {
        var script = File.ReadAllText(Path.Combine(
            RepositoryRoot, "scripts", "Test-IpcBoundary.ps1"));

        Assert.Contains(
            "[string]$CliPath = (Join-Path $PSScriptRoot 'winsight.exe')",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "[string]$ServicePath = (Join-Path $PSScriptRoot 'winsight-firewall-service.exe')",
            script,
            StringComparison.Ordinal);
        Assert.DoesNotContain(@"C:\Program Files\WinSight-VM", script, StringComparison.Ordinal);
        Assert.DoesNotContain("$env:SystemRoot", script, StringComparison.Ordinal);
        Assert.Contains("[switch]$NetworkLogon", script, StringComparison.Ordinal);
        Assert.Contains("'S-1-5-2'", script, StringComparison.Ordinal);
        Assert.Contains("'S-1-5-4'", script, StringComparison.Ordinal);
        Assert.Contains(
            $"$networkRun.ExitCode -eq {CliContract.ServiceUnavailable}",
            script,
            StringComparison.Ordinal);
        Assert.Contains("$networkRun.Available -eq 'false'", script, StringComparison.Ordinal);
        Assert.Contains("$networkRun.Outcome -eq 'ServiceUnavailable'", script, StringComparison.Ordinal);
        Assert.Contains("$networkRun.Mutation -eq 'none'", script, StringComparison.Ordinal);
        Assert.Contains("Result: {0} checks, {1} failure(s).", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Get-CimInstance Win32_Service", script, StringComparison.Ordinal);
        Assert.DoesNotContain("OpenServiceW", script, StringComparison.Ordinal);
    }

    [Fact]
    public void KitSeparatesHostSnapshotsAndRunsNetworkLogonFromASecondMachine()
    {
        var kit = File.ReadAllText(Path.Combine(
            RepositoryRoot, "docs", "validation", "VM_QUALIFICATION_KIT.md"));

        Assert.Contains("HOST ONLY", kit, StringComparison.Ordinal);
        Assert.Contains("VBoxManage.exe", kit, StringComparison.Ordinal);
        Assert.Contains("showvminfo", kit, StringComparison.Ordinal);
        Assert.Contains("host evidence", kit, StringComparison.Ordinal);
        Assert.Contains("second control machine", kit, StringComparison.Ordinal);
        Assert.Contains("Invoke-Command", kit, StringComparison.Ordinal);
        Assert.Contains("-NetworkLogon", kit, StringComparison.Ordinal);
        Assert.Contains("S-1-5-2", kit, StringComparison.Ordinal);
        Assert.Contains("S-1-5-4", kit, StringComparison.Ordinal);
        Assert.Contains("Result: 7 checks, 0 failure(s).", kit, StringComparison.Ordinal);
        Assert.Contains("Result: 3 checks, 0 failure(s).", kit, StringComparison.Ordinal);
        Assert.Contains("-UseSSL", kit, StringComparison.Ordinal);
        Assert.Contains("-Authentication Basic", kit, StringComparison.Ordinal);
        Assert.Contains("New-SelfSignedCertificate", kit, StringComparison.Ordinal);
        Assert.Contains("Test-IpcNetworkObserver.ps1", kit, StringComparison.Ordinal);
        Assert.Contains(
            "-CliPath $Cli -ServicePath $Service",
            kit,
            StringComparison.Ordinal);
    }

    [Fact]
    public void NetworkObserverRequiresElevationAndBindsTheExactServiceInstance()
    {
        var script = File.ReadAllText(Path.Combine(
            RepositoryRoot, "scripts", "Test-IpcNetworkObserver.ps1"));

        Assert.Contains("WindowsBuiltInRole]::Administrator", script, StringComparison.Ordinal);
        Assert.Contains("Get-CimInstance Win32_Service", script, StringComparison.Ordinal);
        Assert.Contains("$expectedCommand", script, StringComparison.Ordinal);
        Assert.Contains("[uint32]$after.ProcessId -eq [uint32]$before.ProcessId", script,
            StringComparison.Ordinal);
        Assert.Contains("Result: 3 checks, 0 failure(s).", script, StringComparison.Ordinal);
    }

    [Fact]
    public void EtwRunbookBindsCapturedProcessesToExactSessionsAndExitEvidence()
    {
        var kit = File.ReadAllText(Path.Combine(
            RepositoryRoot, "docs", "validation", "VM_QUALIFICATION_KIT.md"));

        Assert.Contains("Get-WinSightEtwSessionForProcess", kit, StringComparison.Ordinal);
        Assert.Contains(".Refresh()", kit, StringComparison.Ordinal);
        Assert.Contains(".HasExited", kit, StringComparison.Ordinal);
        Assert.Contains(".WaitForExit", kit, StringComparison.Ordinal);
        Assert.Contains(".ExitCode", kit, StringComparison.Ordinal);
        Assert.Contains("Assert-WinSightEtwSessionsAbsent", kit, StringComparison.Ordinal);
        Assert.Contains("Get-WinSightRuntimeCrashEvents", kit, StringComparison.Ordinal);
    }

    [Fact]
    public void S1ResumeBootstrapRevalidatesExistingProtectedStateWithoutRedeployingIt()
    {
        var kit = File.ReadAllText(Path.Combine(
            RepositoryRoot, "docs", "validation", "VM_QUALIFICATION_KIT.md"));
        var start = kit.IndexOf("### S1 recovery bootstrap", StringComparison.Ordinal);
        var end = kit.IndexOf("## 6.", StringComparison.Ordinal);

        Assert.True(start >= 0 && end > start, "Missing bounded S1 resume bootstrap.");
        var bootstrap = kit[start..end];

        Assert.Contains("function Initialize-WinSightS1QualificationContext", bootstrap, StringComparison.Ordinal);
        Assert.Contains("$ProtectedRoot", bootstrap, StringComparison.Ordinal);
        Assert.Contains("protected-candidate.sha256", bootstrap, StringComparison.Ordinal);
        Assert.Contains("Count -ne 11", bootstrap, StringComparison.Ordinal);
        Assert.Contains("Resolve-Path", bootstrap, StringComparison.Ordinal);
        Assert.Contains("Get-FileHash", bootstrap, StringComparison.Ordinal);
        Assert.Contains("rev-parse HEAD", bootstrap, StringComparison.Ordinal);
        Assert.Contains("status --porcelain", bootstrap, StringComparison.Ordinal);
        Assert.Contains("$CandidateHash = @{}", bootstrap, StringComparison.Ordinal);
        Assert.Contains("function Assert-CandidateFiles", bootstrap, StringComparison.Ordinal);

        var assertCandidate = bootstrap.IndexOf("Assert-CandidateFiles", StringComparison.Ordinal);
        var importModule = bootstrap.IndexOf("Import-Module", StringComparison.Ordinal);
        Assert.True(assertCandidate >= 0 && importModule > assertCandidate,
            "The S1 bootstrap must rehash before importing a protected module.");
        Assert.DoesNotContain("git clone", bootstrap, StringComparison.Ordinal);
        Assert.DoesNotContain("Expand-Archive", bootstrap, StringComparison.Ordinal);
        Assert.DoesNotContain("protected root must be absent", bootstrap, StringComparison.Ordinal);
    }
}
