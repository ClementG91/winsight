using ModelContextProtocol;
using WinSight.Application;
using WinSight.Firewall;
using Xunit;

namespace WinSight.Mcp.Tests;

/// <summary>
/// The outbound-firewall posture tool.
/// </summary>
/// <remarks>
/// This surface is reachable only when the privileged service is installed and running, which no
/// CI runner is, so the reader is behind an interface: without that seam the tool would be
/// untestable except by hand on a provisioned machine, and the honesty rules it exists to carry
/// (requested mode is not proof of filtering, unreachable is not "off") would be unpinned.
/// </remarks>
public sealed class McpOutboundFirewallToolTests
{
    [Fact]
    public async Task SummaryMode_ReportsPostureWithoutListingPolicies()
    {
        var tools = Build(View(
            available: true,
            mode: OutboundFirewallMode.Enforcement,
            effective: FirewallEnforcementState.Active,
            policies: [new AppFirewallPolicy(@"C:\apps\sync.exe", OutboundAction.Block)]));

        var result = await tools.OutboundFirewallAsync();

        Assert.False(result.EvidenceIncluded);
        var report = Assert.Single(result.Reports);
        Assert.Equal("outbound-firewall", report.Tool);
        Assert.Equal("Active", report.Summary);
        Assert.Empty(report.Items);
        // The counts still travel, so a caller learns there is one status line and one policy
        // without being handed the executable paths it did not ask for.
        Assert.Equal(2, report.TotalItemCount);
    }

    [Fact]
    public async Task RequestedEnforcementThatIsNotFiltering_IsReportedAsDegraded()
    {
        // The defect this guards is a sentence, not a crash: a client that reads only "mode" would
        // tell the user their outbound traffic is blocked while nothing is being filtered. Both
        // fields are carried separately, and the summary follows the running state, not the intent.
        var tools = Build(View(
            available: true,
            mode: OutboundFirewallMode.Enforcement,
            effective: FirewallEnforcementState.Degraded));

        var result = await tools.OutboundFirewallAsync(includeEvidence: true);

        var report = Assert.Single(result.Reports);
        Assert.Equal("Degraded", report.Summary);
        var status = Assert.Single(report.Items, item => item.Fields["kind"] == "status");
        Assert.Equal("Enforcement", status.Fields["mode"]);
        Assert.Equal("Degraded", status.Fields["effectiveState"]);
    }

    [Fact]
    public async Task AnUnreachableService_SaysUnavailableAndNeverAuditOnly()
    {
        // A transport fault says nothing about the machine's firewall. Reporting it as "audit-only"
        // would be a claim WinSight cannot support: it would read as "the service is up and not
        // blocking" when the truth is that its state could not be established at all.
        var tools = Build(FirewallServiceView.Unavailable);

        var result = await tools.OutboundFirewallAsync(includeEvidence: true);

        var report = Assert.Single(result.Reports);
        Assert.Equal("Unavailable", report.Summary);
        var status = Assert.Single(report.Items, item => item.Fields["kind"] == "status");
        Assert.Equal("False", status.Fields["available"]);
    }

    [Fact]
    public async Task AnAppNobodyHasRuledOn_SurvivesAsNotable()
    {
        var pending = new PendingOutboundApp(
            @"C:\apps\unknown.exe", "203.0.113.10:443",
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow, Observations: 3);
        var tools = Build(View(available: true, pending: [pending]));

        var result = await tools.OutboundFirewallAsync(includeEvidence: true);

        var report = Assert.Single(result.Reports);
        Assert.Equal(1, report.NotableCount);
        var item = Assert.Single(report.Items, entry => entry.Fields["kind"] == "pending");
        Assert.Equal("notable", item.Severity);
        Assert.Equal("203.0.113.10:443", item.Fields["remote"]);
    }

    [Fact]
    public async Task EvidencePaths_AreRedactedLikeEveryOtherTool()
    {
        // Posture evidence goes through the shared projector, so it inherits the privacy model
        // rather than carrying a second, weaker one of its own.
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var tools = Build(View(
            available: true,
            policies: [new AppFirewallPolicy(Path.Combine(profile, "tools", "agent.exe"), OutboundAction.Allow)]));

        var result = await tools.OutboundFirewallAsync(includeEvidence: true);

        var policy = Assert.Single(result.Reports[0].Items, item => item.Fields["kind"] == "policy");
        Assert.StartsWith("%USERPROFILE%", policy.Fields["path"], StringComparison.Ordinal);
        Assert.DoesNotContain(profile, policy.Fields["path"], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SensitivePaths_StayLockedWithoutTheServerSideSwitch()
    {
        var tools = Build(View(available: true));

        await Assert.ThrowsAsync<McpException>(
            () => tools.OutboundFirewallAsync(includeEvidence: true, includeSensitive: true));
    }

    [Fact]
    public async Task AFailedRead_ReleasesTheGateForTheNextCaller()
    {
        // The service publishes a single pipe instance, so this tool holds a gate. A read that
        // throws must not keep it: the tool would answer once and then refuse forever.
        var reader = new ScriptedReader(_ => throw new InvalidOperationException("pipe fault"));
        var tools = Build(reader);
        await Assert.ThrowsAsync<InvalidOperationException>(() => tools.OutboundFirewallAsync());

        reader.Next = _ => Task.FromResult(FirewallServiceView.Unavailable);
        var result = await tools.OutboundFirewallAsync();

        Assert.Equal("outbound-firewall", result.Reports[0].Tool);
    }

    [Fact]
    public async Task ACancelledRead_SurfacesCancellationRatherThanAnEmptyPosture()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        var tools = Build(View(available: true));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => tools.OutboundFirewallAsync(cancellationToken: cancellation.Token));
    }

    private static FirewallServiceView View(
        bool available,
        OutboundFirewallMode mode = OutboundFirewallMode.AuditOnly,
        FirewallEnforcementState effective = FirewallEnforcementState.AuditOnly,
        IReadOnlyList<AppFirewallPolicy>? policies = null,
        IReadOnlyList<PendingOutboundApp>? pending = null) =>
        new(available, mode, mode == OutboundFirewallMode.Enforcement, policies ?? [], pending ?? [],
            UnrecordedApps: 0, EffectiveState: effective);

    private static WinSightMcpTools Build(FirewallServiceView view) =>
        Build(new ScriptedReader(_ => Task.FromResult(view)));

    private static WinSightMcpTools Build(IFirewallPostureReader reader) => new(
        new McpScanService(),
        new McpSecurityOptions(AllowSensitiveEvidence: false),
        new McpFirewallPostureService(reader));

    private sealed class ScriptedReader(
        Func<CancellationToken, Task<FirewallServiceView>> next) : IFirewallPostureReader
    {
        public Func<CancellationToken, Task<FirewallServiceView>> Next { get; set; } = next;

        public Task<FirewallServiceView> GetViewAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Next(cancellationToken);
        }
    }
}
