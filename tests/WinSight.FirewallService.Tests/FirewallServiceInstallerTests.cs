using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

public sealed class FirewallServiceCommandLineTests
{
    [Theory]
    [InlineData("run", FirewallServiceVerb.Run)]
    [InlineData("install", FirewallServiceVerb.Install)]
    [InlineData("INSTALL", FirewallServiceVerb.Install)]
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
    [InlineData("bogus", FirewallServiceVerb.Unknown)]
    public void Parse_MapsFirstArgumentToVerb(string arg, FirewallServiceVerb expected) =>
        Assert.Equal(expected, FirewallServiceCommandLine.Parse([arg]));

    [Fact]
    public void Parse_NoArguments_DefaultsToRun()
    {
        Assert.Equal(FirewallServiceVerb.Run, FirewallServiceCommandLine.Parse(null));
        Assert.Equal(FirewallServiceVerb.Run, FirewallServiceCommandLine.Parse([]));
    }
}

public sealed class FirewallServiceInstallerTests
{
    [Fact]
    public void BuildBinaryPath_QuotesTheExecutable_AndAppendsRunVerb()
    {
        var binary = FirewallServiceInstaller.BuildBinaryPath(@"C:\Program Files\WinSight\winsight-firewall-service.exe");

        Assert.Equal(@"""C:\Program Files\WinSight\winsight-firewall-service.exe"" run", binary);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void BuildBinaryPath_RejectsEmptyPath(string path) =>
        Assert.Throws<ArgumentException>(() => FirewallServiceInstaller.BuildBinaryPath(path));

    [Fact]
    public void ServiceName_HasNoWhitespace_ForScmCompatibility() =>
        Assert.DoesNotContain(FirewallServiceInstaller.ServiceName, character => char.IsWhiteSpace(character));
}

public sealed class WfpProvisioningTests
{
    [Fact]
    public void WfpObjectKeys_AreStableAndDistinct()
    {
        var keys = new[]
        {
            WfpProvisioning.ProviderKey, WfpProvisioning.SublayerKey,
            WfpProvisioning.PermitFilterKeyV4, WfpProvisioning.PermitFilterKeyV6,
        };
        Assert.DoesNotContain(Guid.Empty, keys);
        Assert.Equal(keys.Length, keys.Distinct().Count());
    }

    [Fact]
    public void BlockFilterKeys_AreStablePerPath_DistinctPerLayer_AndDifferBetweenApps()
    {
        var a1 = WfpProvisioning.BlockFilterKeys(@"C:\apps\a.exe");
        var a2 = WfpProvisioning.BlockFilterKeys(@"C:\apps\a.exe");
        var b = WfpProvisioning.BlockFilterKeys(@"C:\apps\b.exe");

        Assert.Equal(a1, a2);                    // stable across calls
        Assert.NotEqual(a1.V4, a1.V6);           // IPv4 and IPv6 keys differ
        Assert.NotEqual(a1.V4, b.V4);            // different apps get different keys
        Assert.NotEqual(Guid.Empty, a1.V4);
    }

    [Fact]
    public void BlockFilterKeys_AreCaseInsensitiveOnPath()
    {
        Assert.Equal(
            WfpProvisioning.BlockFilterKeys(@"C:\Apps\A.exe"),
            WfpProvisioning.BlockFilterKeys(@"c:\apps\a.exe"));
    }
}

public sealed class WfpOutboundFirewallEngineTests
{
    [Fact]
    public void Engine_ReportsSupported() =>
        Assert.True(new WfpOutboundFirewallEngine().IsSupported);

    [Fact]
    public async Task ApplyAsync_HonoursCancellation()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var engine = new WfpOutboundFirewallEngine();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => engine.ApplyAsync(new WinSight.Firewall.AppFirewallPolicy(@"C:\a.exe", WinSight.Firewall.OutboundAction.Block), cts.Token));
    }
}
