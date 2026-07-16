using WinSight.Firewall;
using Xunit;

namespace WinSight.Application.Tests;

public sealed class FirewallServiceAdapterTests
{
    [Fact]
    public void BuildReport_Unavailable_HasSingleStatusLine()
    {
        var report = FirewallServiceAdapter.BuildReport(FirewallServiceView.Unavailable);

        Assert.Equal(FirewallServiceAdapter.ReportTool, report.Tool);
        var item = Assert.Single(report.Items);
        Assert.Equal("status", item.Fields["kind"]);
        Assert.Equal("False", item.Fields["available"]);
        Assert.Equal(0, report.NotableCount);
    }

    [Fact]
    public void BuildReport_AvailableWithPolicies_EmitsStatusThenPoliciesSorted()
    {
        var view = new FirewallServiceView(
            ServiceAvailable: true,
            OutboundFirewallMode.AuditOnly,
            EnforcementEnabled: false,
            [
                new AppFirewallPolicy(@"C:\apps\b.exe", OutboundAction.Block),
                new AppFirewallPolicy(@"C:\apps\a.exe", OutboundAction.Allow),
            ],
            Pending: []);

        var report = FirewallServiceAdapter.BuildReport(view);

        Assert.Equal(3, report.Items.Count);
        Assert.Equal("status", report.Items[0].Fields["kind"]);
        Assert.Equal("policy", report.Items[1].Fields["kind"]);
        Assert.EndsWith("a.exe", report.Items[1].Fields["path"]!, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("Allow", report.Items[1].Fields["action"]);
        Assert.EndsWith("b.exe", report.Items[2].Fields["path"]!, StringComparison.OrdinalIgnoreCase);
    }

    // An app nobody has ruled on is the one row here that wants a human, so it must survive the
    // "only what needs attention" filter and be listed before the settled policies.
    [Fact]
    public void BuildReport_PendingApp_IsNotableAndComesBeforeSettledPolicies()
    {
        var seen = new DateTimeOffset(2026, 7, 16, 12, 0, 0, TimeSpan.Zero);
        var view = new FirewallServiceView(
            ServiceAvailable: true,
            OutboundFirewallMode.AuditOnly,
            EnforcementEnabled: false,
            [new AppFirewallPolicy(@"C:\apps\ruled.exe", OutboundAction.Allow)],
            [new PendingOutboundApp(@"C:\apps\unknown.exe", "1.2.3.4:443", seen, seen, 3)]);

        var report = FirewallServiceAdapter.BuildReport(view);

        Assert.Equal(3, report.Items.Count);
        Assert.Equal("status", report.Items[0].Fields["kind"]);
        Assert.Equal("pending", report.Items[1].Fields["kind"]);
        Assert.Equal("policy", report.Items[2].Fields["kind"]);
        Assert.Equal(1, report.NotableCount);
    }

    [Fact]
    public void BuildReport_PendingApp_CarriesTheEvidenceADecisionNeeds()
    {
        var first = new DateTimeOffset(2026, 7, 16, 12, 0, 0, TimeSpan.Zero);
        var view = new FirewallServiceView(
            ServiceAvailable: true, OutboundFirewallMode.AuditOnly, EnforcementEnabled: false, [],
            [new PendingOutboundApp(@"C:\apps\unknown.exe", "1.2.3.4:443", first, first.AddMinutes(2), 7)]);

        var item = FirewallServiceAdapter.BuildReport(view).Items[1];

        Assert.Equal(@"C:\apps\unknown.exe", item.Fields["path"]);
        Assert.Equal("1.2.3.4:443", item.Fields["remote"]);
        Assert.Equal("7", item.Fields["observations"]);
        Assert.Equal(first.ToString("o", System.Globalization.CultureInfo.InvariantCulture), item.Fields["firstSeen"]);
    }

    // The blind spot travels to the UI, so a truncated list is never presented as a complete one.
    [Fact]
    public void BuildReport_CarriesWhatTheServiceCouldNotRecord()
    {
        var view = new FirewallServiceView(
            ServiceAvailable: true, OutboundFirewallMode.AuditOnly, EnforcementEnabled: false, [], [],
            UnrecordedApps: 5);

        var status = FirewallServiceAdapter.BuildReport(view).Items[0];

        Assert.Equal("5", status.Fields["unrecorded"]);
    }
}
