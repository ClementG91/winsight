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

    [Fact]
    public void BlockFilterKeys_CanonicalizeQuotedAndRelativeSegments_SameAsClean()
    {
        // Quoted and dot-segmented forms must derive the same key as the clean canonical
        // path, or a block installed via one form is orphaned when re-applied via another.
        var clean = WfpProvisioning.BlockFilterKeys(@"C:\apps\a.exe");
        Assert.Equal(clean, WfpProvisioning.BlockFilterKeys("\"C:\\apps\\a.exe\""));
        Assert.Equal(clean, WfpProvisioning.BlockFilterKeys(@"C:\apps\.\a.exe"));
    }

    [Fact]
    public void BlockFilterKeys_RejectsRelativePath() =>
        Assert.Throws<ArgumentException>(() => WfpProvisioning.BlockFilterKeys(@"a.exe"));
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

public sealed class EnforcementCoordinatorTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(), $"winsight-enforce-{Guid.NewGuid():N}");

    private FirewallPolicyStore Store() =>
        new(Path.Combine(_directory, "policies.json"), allowEnforcement: true);

    [Fact]
    public async Task SetPolicy_Block_PersistsAndAppliesToEngine()
    {
        var store = Store();
        var engine = new RecordingEngine();
        var coordinator = new EnforcementCoordinator(store, engine);

        await coordinator.SetPolicyAsync(@"C:\apps\a.exe", OutboundAction.Block);

        var stored = Assert.Single((await store.LoadAsync()).Policies);
        Assert.Equal(OutboundAction.Block, stored.Action);
        Assert.Contains(engine.Applied, p => p.Action == OutboundAction.Block);
    }

    [Fact]
    public async Task SetPolicy_CanonicalizesPath_SoStoreAndEngineAgree()
    {
        var store = Store();
        var engine = new RecordingEngine();
        var coordinator = new EnforcementCoordinator(store, engine);

        await coordinator.SetPolicyAsync("\"C:\\apps\\a.exe\"", OutboundAction.Block);

        var stored = Assert.Single((await store.LoadAsync()).Policies);
        Assert.Equal(@"C:\apps\a.exe", stored.ExecutablePath);
        Assert.Equal(@"C:\apps\a.exe", Assert.Single(engine.Applied).ExecutablePath);
    }

    [Fact]
    public async Task Enable_PersistsEnforcement_AndAppliesOnlyBlockPolicies()
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.AuditOnly,
        [
            new AppFirewallPolicy(@"C:\apps\block.exe", OutboundAction.Block),
            new AppFirewallPolicy(@"C:\apps\allow.exe", OutboundAction.Allow),
        ]));
        var engine = new RecordingEngine();
        var coordinator = new EnforcementCoordinator(store, engine);

        await coordinator.EnableAsync();

        Assert.Equal(OutboundFirewallMode.Enforcement, await coordinator.GetModeAsync());
        var applied = Assert.Single(engine.Applied);
        Assert.EndsWith("block.exe", applied.ExecutablePath, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Disable_LiftsEveryFilter_ThenPersistsAuditOnly()
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.Enforcement,
            [new AppFirewallPolicy(@"C:\apps\block.exe", OutboundAction.Block)]));
        var engine = new RecordingEngine();
        var coordinator = new EnforcementCoordinator(store, engine);

        await coordinator.DisableAsync();

        Assert.Contains(engine.Removed, path => path.EndsWith("block.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(OutboundFirewallMode.AuditOnly, await coordinator.GetModeAsync());
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private sealed class RecordingEngine : IOutboundFirewallEngine
    {
        public List<AppFirewallPolicy> Applied { get; } = [];

        public List<string> Removed { get; } = [];

        public bool IsSupported => true;

        public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        {
            Applied.Add(policy);
            return Task.CompletedTask;
        }

        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default)
        {
            Removed.Add(executablePath);
            return Task.CompletedTask;
        }
    }
}
