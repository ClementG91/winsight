using System.ComponentModel;
using WinSight.Firewall;
using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

public sealed class FirewallServiceCommandLineTests
{
    [Theory]
    [InlineData("run", FirewallServiceVerb.Run)]
    [InlineData("install", FirewallServiceVerb.Install)]
    [InlineData("INSTALL", FirewallServiceVerb.Install)]
    [InlineData("install-path-trust-check", FirewallServiceVerb.InstallPathTrustCheck)]
    [InlineData("INSTALL-PATH-TRUST-CHECK", FirewallServiceVerb.InstallPathTrustCheck)]
    [InlineData("uninstall", FirewallServiceVerb.Uninstall)]
    [InlineData("remove", FirewallServiceVerb.Uninstall)]
    [InlineData("status", FirewallServiceVerb.Status)]
    [InlineData("wfp-selftest", FirewallServiceVerb.WfpSelfTest)]
    [InlineData("wfp-provision", FirewallServiceVerb.WfpProvision)]
    [InlineData("wfp-deprovision", FirewallServiceVerb.WfpDeprovision)]
    [InlineData("wfp-status", FirewallServiceVerb.WfpStatus)]
    [InlineData("wfp-filter-add", FirewallServiceVerb.WfpFilterAdd)]
    [InlineData("wfp-filter-remove", FirewallServiceVerb.WfpFilterRemove)]
    [InlineData("wfp-block-add", FirewallServiceVerb.WfpBlockAdd)]
    [InlineData("wfp-block-remove", FirewallServiceVerb.WfpBlockRemove)]
    [InlineData("wfp-block-status", FirewallServiceVerb.WfpBlockStatus)]
    [InlineData("enforce-status", FirewallServiceVerb.EnforceStatus)]
    [InlineData("enforce-enable", FirewallServiceVerb.EnforceEnable)]
    [InlineData("enforce-disable", FirewallServiceVerb.EnforceDisable)]
    [InlineData("block-app", FirewallServiceVerb.BlockApp)]
    [InlineData("allow-app", FirewallServiceVerb.AllowApp)]
    [InlineData("bogus", FirewallServiceVerb.Unknown)]
    public void Parse_MapsFirstArgumentToVerb(string arg, FirewallServiceVerb expected) =>
        Assert.Equal(expected, FirewallServiceCommandLine.Parse([arg]));

    [Fact]
    public void Parse_NoArguments_DefaultsToRun()
    {
        Assert.Equal(FirewallServiceVerb.Run, FirewallServiceCommandLine.Parse(null));
        Assert.Equal(FirewallServiceVerb.Run, FirewallServiceCommandLine.Parse([]));
    }

    [Fact]
    public void CliDiagnosticSink_StaticContractUsesInvariantCodesWithoutInterpolation()
    {
        var programPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
            "..", "..", "..", "..", "..", "src", "WinSight.FirewallService", "Program.cs"));
        var commandHostPath = Path.Combine(Path.GetDirectoryName(programPath)!, "FirewallServiceCommandHost.cs");
        var programSource = File.ReadAllText(programPath);
        var commandHostSource = File.ReadAllText(commandHostPath);
        var diagnosticSources = programSource + commandHostSource;

        Assert.DoesNotContain("Console.Error.WriteLine($", programSource, StringComparison.Ordinal);
        Assert.Contains(
            "new FirewallServiceCommandHost(",
            programSource,
            StringComparison.Ordinal);
        Assert.Contains(".Execute(args, Console.Out, Console.Error);", programSource, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "FirewallServiceVerb.InstallPathTrustCheck =>",
            programSource,
            StringComparison.Ordinal);
        Assert.Contains("standardError.WriteLine(result.StandardError);", commandHostSource, StringComparison.Ordinal);
        foreach (var code in new[]
        {
            "[FW_INSTALL_FAILED]", "[FW_UNINSTALL_FAILED]", "[FW_SERVICE_STATUS_UNAVAILABLE]",
            "[FW_STORAGE_PROVISIONING_FAILED]", "[FW_STORAGE_UNTRUSTED]",
            "[FW_ENFORCEMENT_STATUS_UNAVAILABLE]",
        })
        {
            Assert.Contains(code, diagnosticSources, StringComparison.Ordinal);
        }
    }
}
