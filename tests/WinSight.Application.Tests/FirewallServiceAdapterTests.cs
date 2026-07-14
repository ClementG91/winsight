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
            ]);

        var report = FirewallServiceAdapter.BuildReport(view);

        Assert.Equal(3, report.Items.Count);
        Assert.Equal("status", report.Items[0].Fields["kind"]);
        Assert.Equal("policy", report.Items[1].Fields["kind"]);
        Assert.EndsWith("a.exe", report.Items[1].Fields["path"]!, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("Allow", report.Items[1].Fields["action"]);
        Assert.EndsWith("b.exe", report.Items[2].Fields["path"]!, StringComparison.OrdinalIgnoreCase);
    }
}
