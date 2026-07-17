using Xunit;

namespace WinSight.FirewallService.Tests;

public sealed class FirewallDocumentationContractTests
{
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
        Assert.Contains("condition.Type == FwpByteBlobType", source, StringComparison.Ordinal);
        Assert.Contains("condition.Value.AsSpan().SequenceEqual(expected.AppId)", source,
            StringComparison.Ordinal);
    }

    private static string Read(params string[] segments) =>
        File.ReadAllText(Path.Combine([RepositoryRoot, .. segments]));
}
