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
        var observer = Observer(log, new StubResolver { [4242] = @"C:\apps\unknown.exe" });

        observer.OnConnection(new OutboundConnectionEvent(4242, "93.184.216.34", 443));

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
        var observer = Observer(log, new StubResolver { [7] = @"C:\apps\known.exe" }, store);

        observer.OnConnection(new OutboundConnectionEvent(7, "93.184.216.34", 443));

        Assert.Empty(log.Snapshot());
    }

    // A process that exits between connecting and being asked about cannot be attributed. Counting
    // it is the difference between a known blind spot and a silent one.
    [Fact]
    public void OnConnection_CountsWhatItCannotAttribute_RatherThanGuessing()
    {
        var log = new PendingOutboundLog();
        var observer = Observer(log, new StubResolver());

        observer.OnConnection(new OutboundConnectionEvent(999, "93.184.216.34", 443));

        Assert.Empty(log.Snapshot());
        Assert.Equal(1, observer.UnattributedConnections);
    }

    [Fact]
    public void OnConnection_CountsAPathNoPolicyCouldBeKeyedOn()
    {
        var log = new PendingOutboundLog();
        var observer = Observer(log, new StubResolver { [7] = "not-absolute.exe" });

        observer.OnConnection(new OutboundConnectionEvent(7, "93.184.216.34", 443));

        Assert.Empty(log.Snapshot());
        Assert.Equal(1, observer.UnattributedConnections);
    }

    // The resolver must be asked every time: Windows reuses process ids, so a cached answer
    // eventually names a different program than the one that connected.
    [Fact]
    public void OnConnection_ResolvesEveryConnection_SoAReusedProcessIdCannotMisattribute()
    {
        var log = new PendingOutboundLog();
        var resolver = new StubResolver { [100] = @"C:\apps\first.exe" };
        var observer = Observer(log, resolver);

        observer.OnConnection(new OutboundConnectionEvent(100, "1.2.3.4", 443));
        resolver[100] = @"C:\apps\second.exe";   // the id was reused by another program
        observer.OnConnection(new OutboundConnectionEvent(100, "1.2.3.4", 443));

        Assert.Equal(2, resolver.Calls);
        Assert.Equal(
            [@"C:\apps\first.exe", @"C:\apps\second.exe"],
            log.Snapshot().Select(app => app.ExecutablePath).OrderBy(path => path, StringComparer.Ordinal));
    }

    // The snapshot is reused for a few seconds so file IO stays off the ETW callback path; a
    // decision taken meanwhile must still be picked up once it goes stale.
    [Fact]
    public async Task OnConnection_PicksUpADecisionAfterTheSnapshotGoesStale()
    {
        var log = new PendingOutboundLog();
        var store = new FirewallPolicyStore(PolicyPath);
        var time = new TestClock(new DateTimeOffset(2026, 7, 16, 12, 0, 0, TimeSpan.Zero));
        var observer = Observer(log, new StubResolver { [7] = @"C:\apps\a.exe" }, store, time);

        observer.OnConnection(new OutboundConnectionEvent(7, "1.2.3.4", 443));
        Assert.Single(log.Snapshot());

        await store.SaveAsync(OutboundFirewallConfiguration.Empty with
        {
            Policies = [new AppFirewallPolicy(@"C:\apps\a.exe", OutboundAction.Allow)],
        });
        log.Resolve(@"C:\apps\a.exe");
        time.Advance(TimeSpan.FromSeconds(30));

        observer.OnConnection(new OutboundConnectionEvent(7, "1.2.3.4", 443));

        Assert.Empty(log.Snapshot());
    }

    private OutboundObserverService Observer(
        PendingOutboundLog log,
        IProcessImageResolver resolver,
        FirewallPolicyStore? store = null,
        TimeProvider? time = null) =>
        new(new OutboundConnectionWatcher(), resolver, store ?? new FirewallPolicyStore(PolicyPath), log,
            NullLogger<OutboundObserverService>.Instance, time);

    private sealed class StubResolver : IProcessImageResolver
    {
        private readonly Dictionary<int, string> _paths = [];
        public int Calls { get; private set; }
        public string this[int pid] { set => _paths[pid] = value; }
        public string? Resolve(int processId)
        {
            Calls++;
            return _paths.GetValueOrDefault(processId);
        }
    }

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
