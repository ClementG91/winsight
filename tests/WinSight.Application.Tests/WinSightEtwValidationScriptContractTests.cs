using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// The VM ETW inventory runs elevated. It must not resolve logman through an attacker-controlled
/// PATH, even when the module is imported from the protected candidate tree.
/// </summary>
public sealed class WinSightEtwValidationScriptContractTests
{
    private static readonly string RepositoryRoot = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    [Fact]
    public void InventoryUsesOnlyTheExplicitSystemDirectoryLogmanBinary()
    {
        var module = File.ReadAllText(Path.Combine(
            RepositoryRoot, "scripts", "WinSightEtwValidation.psm1"));

        Assert.Contains("[Environment]::SystemDirectory", module, StringComparison.Ordinal);
        Assert.Contains("[IO.Path]::Combine($systemDirectory, 'logman.exe')", module, StringComparison.Ordinal);
        Assert.Contains("[IO.File]::Exists($logmanPath)", module, StringComparison.Ordinal);
        Assert.Contains("& $logmanPath query -ets", module, StringComparison.Ordinal);
        Assert.DoesNotContain("& logman query -ets", module, StringComparison.Ordinal);
        Assert.DoesNotContain("$env:SystemRoot", module, StringComparison.Ordinal);
    }

    [Fact]
    public void ModuleExportsFailClosedRuntimeAndExactProcessSessionOracles()
    {
        var module = File.ReadAllText(Path.Combine(
            RepositoryRoot, "scripts", "WinSightEtwValidation.psm1"));

        Assert.Contains("function Get-WinSightRuntimeCrashEvents", module, StringComparison.Ordinal);
        Assert.Contains("Microsoft.PowerShell.Diagnostics\\Get-WinEvent", module, StringComparison.Ordinal);
        Assert.Contains(
            "NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand",
            module,
            StringComparison.Ordinal);
        Assert.Contains("ETW crash gate is STOP", module, StringComparison.Ordinal);
        Assert.Contains("function Get-WinSightEtwSessionForProcess", module, StringComparison.Ordinal);
        Assert.Contains("Expected exactly one WinSight $Family v2 ETW session", module, StringComparison.Ordinal);
    }
}
