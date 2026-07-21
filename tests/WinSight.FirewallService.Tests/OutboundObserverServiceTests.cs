using Microsoft.Extensions.Logging.Abstractions;
using WinSight.Firewall;
using WinSight.FirewallService;
using WinSight.NetMonitor;
using Xunit;

namespace WinSight.FirewallService.Tests;

public sealed class OutboundObserverServiceTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(), $"winsight-observer-{Guid.NewGuid():N}");

    private string PolicyPath => Path.Combine(_directory, "policies.json");

    public OutboundObserverServiceTests() => Directory.CreateDirectory(_directory);

    [Fact]
    public void OnConnection_RecordsAnAppWithNoPolicy()
    {
        var log = new PendingOutboundLog();
        var observer = Observer(log);

        observer.OnConnection(Connection(@"C:\apps\unknown.exe", "93.184.216.34", 443));

        var app = Assert.Single(log.Snapshot());
        Assert.Equal(@"C:\apps\unknown.exe", app.ExecutablePath);
        Assert.Equal("93.184.216.34:443", app.LastRemote);
    }

    // An app the operator already ruled on is not news, and letting routine traffic into the log
    // would fill the cap and push genuinely unknown apps out of it.
    [Theory]
    [InlineData(OutboundAction.Allow)]
    [InlineData(OutboundAction.Block)]
    public async Task OnConnection_IgnoresAnAppTheOperatorAlreadyRuledOn(OutboundAction action)
    {
        var store = new FirewallPolicyStore(PolicyPath);
        await store.SaveAsync(OutboundFirewallConfiguration.Empty with
        {
            Policies = [new AppFirewallPolicy(@"C:\apps\known.exe", action)],
        });
        var log = new PendingOutboundLog();
        var observer = Observer(log, store);

        observer.OnConnection(Connection(@"C:\apps\known.exe", "93.184.216.34", 443));

        Assert.Empty(log.Snapshot());
    }

    [Fact]
    public void OnConnection_CountsAPathNoPolicyCouldBeKeyedOn()
    {
        var log = new PendingOutboundLog();
        var observer = Observer(log);

        observer.OnConnection(Connection("not-absolute.exe", "93.184.216.34", 443));

        Assert.Empty(log.Snapshot());
        Assert.Equal(1, observer.UnattributedConnections);
    }

    // The counter existed but could never count the case it is named for: the watcher dropped a
    // connection whose process it could not name before this service ever saw it, so a machine
    // losing connections reported zero unattributed. Measured live, that population is exactly the
    // bare-name launches — powershell.exe, cmd, node — which is the traffic worth knowing about.
    [Fact]
    public void OnUnattributedConnection_CountsAConnectionTheWatcherCouldNotName()
    {
        var log = new PendingOutboundLog();
        var observer = Observer(log);

        observer.OnUnattributedConnection(4242, "powershell.exe");
        observer.OnUnattributedConnection(4243, imageName: null);

        Assert.Equal(2, observer.UnattributedConnections);
        // Never into the pending log: that log is the list of apps the operator can Allow or Block,
        // and a bare name is not something a rule may be keyed on.
        Assert.Empty(log.Snapshot());
    }

    // The snapshot is reused for a few seconds so file IO stays off the trace callback path; a
    // decision taken meanwhile must still be picked up once it goes stale.
    [Fact]
    public async Task OnConnection_PicksUpADecisionAfterTheSnapshotGoesStale()
    {
        var log = new PendingOutboundLog();
        var store = new FirewallPolicyStore(PolicyPath);
        var time = new TestClock(new DateTimeOffset(2026, 7, 16, 12, 0, 0, TimeSpan.Zero));
        var observer = Observer(log, store, time);

        observer.OnConnection(Connection(@"C:\apps\a.exe", "1.2.3.4", 443));
        Assert.Single(log.Snapshot());

        await store.SaveAsync(OutboundFirewallConfiguration.Empty with
        {
            Policies = [new AppFirewallPolicy(@"C:\apps\a.exe", OutboundAction.Allow)],
        });
        log.Resolve(@"C:\apps\a.exe");
        time.Advance(TimeSpan.FromSeconds(30));

        observer.OnConnection(Connection(@"C:\apps\a.exe", "1.2.3.4", 443));

        Assert.Empty(log.Snapshot());
    }

    [Fact]
    public void OnConnection_CountsOneAppOnce_HoweverOftenItConnects()
    {
        var log = new PendingOutboundLog();
        var observer = Observer(log);

        for (var i = 0; i < 5; i++)
        {
            observer.OnConnection(Connection(@"C:\apps\a.exe", "1.2.3.4", 443 + i));
        }

        var app = Assert.Single(log.Snapshot());
        Assert.Equal(5, app.Observations);
    }

    private static OutboundConnectionEvent Connection(string path, string address, int port) =>
        new(4242, path, address, port);

    private OutboundObserverService Observer(
        PendingOutboundLog log, FirewallPolicyStore? store = null, TimeProvider? time = null) =>
        new(new OutboundConnectionWatcher(), store ?? new FirewallPolicyStore(PolicyPath), log,
            NullLogger<OutboundObserverService>.Instance, time);

    // TimeProvider is in the BCL and abstract, so controlling the clock costs a few lines rather
    // than a test-only package.
    private sealed class TestClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan delta) => _now += delta;
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}
