using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// RA-05: uninstalling an all-users installation must stop, not carry on, when the firewall service
/// that runs from it cannot be removed. Carrying on deleted the program and left the dangling
/// LocalSystem service WS-63 exists to prevent.
/// </summary>
/// <remarks>
/// ISCC compiles the script, and the VM gate runs it (<c>Test-InstallerServiceUninstall.ps1</c>,
/// the blocked-service case); nothing in the unit suite executes Pascal Script. These source
/// contracts keep the policy, and the gate that proves it, from sliding back to "report and continue".
/// </remarks>
public sealed class InstallerUninstallContractTests
{
    private static readonly string RepositoryRoot = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    private static string Read(params string[] relative) =>
        File.ReadAllText(Path.Combine([RepositoryRoot, .. relative])).ReplaceLineEndings("\n");

    private static string Between(string text, string start, string end)
    {
        var from = text.IndexOf(start, StringComparison.Ordinal);
        Assert.True(from >= 0, $"'{start}' not found");
        var to = text.IndexOf(end, from + start.Length, StringComparison.Ordinal);
        Assert.True(to > from, $"'{end}' not found after '{start}'");
        return text[from..to];
    }

    [Fact]
    public void AFailedServiceRemovalStopsTheUninstallBeforeAnythingIsDeleted()
    {
        var script = Read("installer", "WinSight.iss");

        var removal = Between(script, "procedure RemoveFirewallServiceOfThisInstallation();", "procedure CurUninstallStepChanged");
        // Raised from usUninstall, an exception is fatal to Inno before [UninstallRun] and deletion.
        Assert.Contains("RaiseException(FmtMessage(CustomMessage('FirewallServiceNotRemoved'), [Expected]));", removal, StringComparison.Ordinal);
        // A dialog followed by the deletion was the defect.
        Assert.DoesNotContain("MsgBox(", removal, StringComparison.Ordinal);

        var step = Between(script, "procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);", "function GetDashboardLanguage");
        Assert.Contains("if CurUninstallStep = usUninstall then", step, StringComparison.Ordinal);
        Assert.Contains("RemoveFirewallServiceOfThisInstallation();", step, StringComparison.Ordinal);
    }

    [Fact]
    public void TheMessageGivesTheRecoveryAndNeverAsksForActionBeforeADeletion()
    {
        var messages = Read("installer", "WinSight.iss").Split('\n')
            .Where(line => line.Contains(".FirewallServiceNotRemoved=", StringComparison.Ordinal))
            .ToList();

        Assert.Equal(3, messages.Count);
        Assert.All(messages, message =>
        {
            Assert.Contains("\"%1\" uninstall", message, StringComparison.Ordinal);
            Assert.Contains("sc delete WinSightFirewall", message, StringComparison.Ordinal);
            Assert.DoesNotContain("before deleting", message, StringComparison.Ordinal);
            Assert.DoesNotContain("avant de supprimer ce fichier", message, StringComparison.Ordinal);
            Assert.DoesNotContain("antes de eliminar ese archivo", message, StringComparison.Ordinal);
        });
    }

    [Fact]
    public void TheVmGateInjectsTheFailureAndRequiresNothingRemoved()
    {
        var gate = Read("scripts", "Test-InstallerServiceUninstall.ps1");

        Assert.Contains("(D;;SD;;;BA)(D;;SD;;;SY)", gate, StringComparison.Ordinal);
        Assert.Contains("The service program was deleted under a registered service.", gate, StringComparison.Ordinal);
        Assert.Contains("PASS blocked-service", gate, StringComparison.Ordinal);
        Assert.Contains("Assert-NoWinSightWfpObject", gate, StringComparison.Ordinal);
    }
}
