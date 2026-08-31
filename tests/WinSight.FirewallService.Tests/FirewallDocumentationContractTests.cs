using Xunit;

namespace WinSight.FirewallService.Tests;

public sealed class FirewallDocumentationContractTests
{
    [Fact]
    public void ServiceHostCapturesItsExitSignalBeforeDisposingTheProvider()
    {
        var source = Read("src", "WinSight.FirewallService", "Program.cs");
        var capture = source.IndexOf(
            "var exitSignal = host.Services.GetRequiredService<FirewallServiceExitSignal>();",
            StringComparison.Ordinal);
        var run = source.IndexOf("await host.RunAsync()", StringComparison.Ordinal);
        var dispose = source.IndexOf("await asyncHost.DisposeAsync()", StringComparison.Ordinal);
        var result = source.IndexOf("return exitSignal.ExitCode;", StringComparison.Ordinal);

        Assert.True(capture >= 0, "The exit signal must be resolved while the host provider is alive.");
        Assert.True(capture < run, "The exit signal must be captured before the host begins teardown.");
        Assert.True(run < dispose, "Host disposal must remain after RunAsync.");
        Assert.True(dispose < result, "The captured signal may be read after host disposal.");
        Assert.DoesNotContain(
            "return host.Services.GetRequiredService<FirewallServiceExitSignal>()",
            source,
            StringComparison.Ordinal);
    }

    private static readonly string RepositoryRoot = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    [Fact]
    public void EnforceStatus_LabelsPersistedIntentAndNeverClaimsRuntimeActive()
    {
        var source = Read("src", "WinSight.FirewallService", "Program.cs");

        Assert.Contains(
            "Persisted desired enforcement mode: {mode}. Effective runtime state: unknown",
            source,
            StringComparison.Ordinal);
        Assert.Contains("[FW_ENFORCEMENT_STATUS_UNAVAILABLE]", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Enforcement mode: {mode}", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Effective runtime state: Active", source, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ProductDocs_DescribeV3AuthenticatedIpcRebootAndDesiredEffectiveTruth()
    {
        var readme = Read("README.md");
        var design = Read("docs", "WFP_DESIGN.md");
        var installation = Read("docs", "INSTALLATION.md");
        var arm64 = Read("docs", "ARM64_VALIDATION.md");

        Assert.Contains("authenticated named-pipe", readme, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("IPC", readme, StringComparison.Ordinal);
        Assert.Contains("desired", readme, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("effective", readme, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("boot persistence", readme, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Firewall IPC v3", design, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("SnapshotChanged", design, StringComparison.Ordinal);
        Assert.Contains("auto-start", design, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("[FW_DIRECT_MUTATION_DISABLED]", installation, StringComparison.Ordinal);
        Assert.Contains("persisted desired", arm64, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("effective runtime unknown", arm64, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CurrentProductSurfaces_DoNotRepeatRemovedAuditOnlyOrDirectMutationClaims()
    {
        var surfaces = new[]
        {
            Read("README.md"),
            Read("docs", "WFP_DESIGN.md"),
            Read("docs", "INSTALLATION.md"),
            Read("docs", "DETECTIONS.md"),
            Read("docs", "ARM64_VALIDATION.md"),
            Read("src", "WinSight.Firewall", "NamedPipeFirewallServer.cs"),
            Read("src", "WinSight.FirewallService", "Program.cs"),
            Read("src", "WinSight.FirewallService", "FirewallServiceInstaller.cs"),
        };

        foreach (var surface in surfaces)
        {
            Assert.DoesNotContain("does not apply WFP", surface, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("does not create WFP", surface, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("audit-only named pipe", surface, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("enforcement is a future", surface, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void WfpExactInventorySourceChecksContainersEnumerationAndCompleteFilterShape()
    {
        // This is deliberately a source-shape guard, not native validation. The x64/Arm64
        // VM gate must still exercise every P/Invoke against real BFE/WFP state.
        //
        // It also is not, and never was, a check on what the predicate *does*: it greps for
        // substrings, so a clause deleted from the expression is invisible to it unless the
        // substring happens to be listed. Two were not — MatchType and the null-value check — and
        // removing the MatchType clause left this test green while accepting a filter that matches
        // on NOT-equal, i.e. one blocking every program except the named one. WfpExactShapeTests
        // now falsifies every clause behaviourally; the list below is kept as a second, cheaper net
        // over the native call names this cannot otherwise reach.
        var source = Read("src", "WinSight.FirewallService", "WfpProvisioning.cs");

        Assert.Contains("FwpmProviderGetByKey0", source, StringComparison.Ordinal);
        Assert.Contains("FwpmSubLayerGetByKey0", source, StringComparison.Ordinal);
        Assert.Contains("FwpmFilterEnum0", source, StringComparison.Ordinal);
        Assert.Contains("owned.Count != expected.Count", source, StringComparison.Ordinal);
        Assert.Contains("filter.ProviderKey == ProviderKey", source, StringComparison.Ordinal);
        Assert.Contains("filter.SubLayerKey == SublayerKey", source, StringComparison.Ordinal);
        Assert.Contains("filter.LayerKey == expected.LayerKey", source, StringComparison.Ordinal);
        Assert.Contains("filter.ActionType == FwpActionBlock", source, StringComparison.Ordinal);
        Assert.Contains("filter.ConditionCount == 1", source, StringComparison.Ordinal);
        Assert.Contains("condition.FieldKey == AleAppIdCondition", source, StringComparison.Ordinal);
        // Both were missing from this list. Matching on anything but equality inverts the filter,
        // and a null value would compare an app-id blob that is not there.
        Assert.Contains("condition.MatchType == FwpMatchEqual", source, StringComparison.Ordinal);
        Assert.Contains("condition.Value is not null", source, StringComparison.Ordinal);
        Assert.Contains("condition.Type == FwpByteBlobType", source, StringComparison.Ordinal);
        Assert.Contains("condition.Value.AsSpan().SequenceEqual(expected.AppId)", source,
            StringComparison.Ordinal);

        // Regression: the exact-shape check must mask the INDEXED flag WFP sets on its own, not
        // require Flags == 0. On a live machine, "filter.Flags == 0" rejected every real block and
        // turned working enforcement into a false "degraded" with a protection-destroying rollback.
        Assert.Contains("FilterFlagsAreClean(filter.Flags)", source, StringComparison.Ordinal);
        Assert.DoesNotContain("filter.Flags == 0", source, StringComparison.Ordinal);

        // BFE assigns the closest available sublayer weight. Requiring literal 0x8000 reproduced a
        // live false degraded state when Windows returned 0x8001, so the shape check must use the
        // bounded verifier instead of exact equality.
        Assert.Contains("SublayerWeightIsAcceptable(sublayer.Weight)", source, StringComparison.Ordinal);
        Assert.DoesNotContain("sublayer.Weight == SublayerWeight", source, StringComparison.Ordinal);
    }

    // WFP sets FWPM_FILTER_FLAG_INDEXED (0x40) on any app-id filter itself, so a correctly applied
    // block reads back with it. It must be accepted; every other flag stays disqualifying because
    // WinSight never creates a persistent, boot-time or disabled filter.
    [Theory]
    [InlineData(0x00u, true)]   // no flags
    [InlineData(0x40u, true)]   // INDEXED, set by WFP — the one that broke enforcement
    [InlineData(0x01u, false)]  // PERSISTENT — never created by WinSight
    [InlineData(0x02u, false)]  // BOOTTIME
    [InlineData(0x41u, false)]  // INDEXED + PERSISTENT: the extra flag still disqualifies
    public void FilterFlagsAreClean_AcceptsOnlyTheIndexFlagWfpSetsItself(uint flags, bool expected) =>
        Assert.Equal(expected, WfpProvisioning.FilterFlagsAreClean(flags));

    [Theory]
    [InlineData(0x8000, true)]  // requested value
    [InlineData(0x8001, true)]  // value observed from BFE in native VM qualification
    [InlineData(0x7FFF, true)]  // the equally-close lower neighbour is also valid
    [InlineData(0x7000, true)]  // lower bound of the accepted arbitration band
    [InlineData(0x9000, true)]  // upper bound of the accepted arbitration band
    [InlineData(0x6FFF, false)]
    [InlineData(0x9001, false)]
    [InlineData(0x0000, false)] // historical floor weight must be rebuilt
    [InlineData(0xFFFF, false)]
    public void SublayerWeightIsAcceptable_AllowsOnlyBoundedBfeDrift(
        ushort actualWeight,
        bool expected) =>
        Assert.Equal(expected, WfpProvisioning.SublayerWeightIsAcceptable(actualWeight));

    private static string Read(params string[] segments) =>
        File.ReadAllText(Path.Combine([RepositoryRoot, .. segments]));
}
