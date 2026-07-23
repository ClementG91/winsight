using System.ComponentModel;
using WinSight.Firewall;
using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

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
