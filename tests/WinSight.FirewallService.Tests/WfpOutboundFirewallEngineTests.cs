using System.ComponentModel;
using WinSight.Firewall;
using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

public sealed class WfpOutboundFirewallEngineTests
{
    [Fact]
    public void Engine_ReportsSupported()
    {
        using var engine = new WfpOutboundFirewallEngine(() => new RecordingSession());

        Assert.True(engine.IsSupported);
    }

    [Fact]
    public async Task ApplyAsync_HonoursCancellation()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var created = 0;
        using var engine = new WfpOutboundFirewallEngine(() =>
        {
            created++;
            return new RecordingSession();
        });

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => engine.ApplyAsync(new WinSight.Firewall.AppFirewallPolicy(@"C:\a.exe", WinSight.Firewall.OutboundAction.Block), cts.Token));
        Assert.Equal(0, created);
    }

    [Fact]
    public async Task ReconcileVerifyAndCleanup_ReuseOneOwnedSession()
    {
        var session = new RecordingSession { VerificationResult = true };
        using var engine = new WfpOutboundFirewallEngine(() => session);
        AppFirewallPolicy[] policies = [new(@"C:\a.exe", OutboundAction.Block)];

        await engine.ReconcileExactAsync(policies);
        var verified = await engine.VerifyExactAsync(policies);
        await engine.CleanupAllAsync();

        Assert.True(verified);
        Assert.Equal(1, session.ReconcileCalls);
        Assert.Equal(1, session.VerifyCalls);
        Assert.Equal(1, session.CleanupCalls);
    }

    [Fact]
    public async Task Dispose_ClosesTheOwnedSessionOnceAndRejectsFurtherWork()
    {
        var session = new RecordingSession();
        var engine = new WfpOutboundFirewallEngine(() => session);
        await engine.CleanupAllAsync();

        engine.Dispose();
        engine.Dispose();

        Assert.Equal(1, session.DisposeCalls);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => engine.CleanupAllAsync());
    }

    private sealed class RecordingSession : IWinSightWfpSession
    {
        public int ReconcileCalls { get; private set; }
        public int VerifyCalls { get; private set; }
        public int CleanupCalls { get; private set; }
        public int DisposeCalls { get; private set; }
        public bool VerificationResult { get; init; }

        public void Provision() { }
        public void AddBlock(string executablePath) { }
        public void RemoveBlock(string executablePath) { }

        public void ReconcileExact(IReadOnlyList<AppFirewallPolicy> policies) => ReconcileCalls++;

        public bool VerifyExact(IReadOnlyList<AppFirewallPolicy> policies)
        {
            VerifyCalls++;
            return VerificationResult;
        }

        public void CleanupAll() => CleanupCalls++;
        public void Dispose() => DisposeCalls++;
    }
}
