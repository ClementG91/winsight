using System.Collections.Concurrent;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using WinSight.Firewall;
using WinSight.FirewallService;
using WinSight.NetMonitor;
using Xunit;

namespace WinSight.FirewallService.Tests;

public sealed class OutboundObserverServiceTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(), $"winsight-observer-{Guid.NewGuid():N}");

    // Every observer this class builds, so teardown can wait for their background reloads the way
    // the service's own StopAsync does.
    private readonly List<OutboundObserverService> _observers = [];

    private string PolicyPath => Path.Combine(_directory, "policies.json");

    public OutboundObserverServiceTests() => Directory.CreateDirectory(_directory);

    public Task InitializeAsync() => Task.CompletedTask;

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
        // What the service awaits once at startup. Awaited here rather than left to the background
        // refresh, because the point of that refresh is that it does not happen on this path.
        await observer.RefreshRuledAsync();

        observer.OnConnection(Connection(@"C:\apps\known.exe", "93.184.216.34", 443));

        Assert.Empty(log.Snapshot());
    }

    [Theory]
    [InlineData(OutboundAction.Ask, true)]
    [InlineData(OutboundAction.Allow, false)]
    [InlineData(OutboundAction.Block, false)]
    public async Task OnConnection_TreatsAskAndDisabledRowsAsUnresolved(
        OutboundAction action,
        bool enabled)
    {
        var store = new FirewallPolicyStore(PolicyPath);
        await store.SaveAsync(OutboundFirewallConfiguration.Empty with
        {
            Policies = [new AppFirewallPolicy(@"C:\apps\unresolved.exe", action, enabled)],
        });
        var log = new PendingOutboundLog();
        var observer = Observer(log, store);
        await observer.RefreshRuledAsync();

        observer.OnConnection(Connection(@"C:\apps\unresolved.exe", "93.184.216.34", 443));

        Assert.Single(log.Snapshot());
    }

    [Fact]
    public void OnConnection_CountsAPathNoPolicyCouldBeKeyedOn()
    {
        var log = new PendingOutboundLog();
        var observer = Observer(log);

        observer.OnConnection(Connection("not-absolute.exe", "93.184.216.34", 443));

        Assert.Empty(log.Snapshot());
        Assert.Equal(1, observer.UnattributedConnections);
        Assert.Equal(1, log.UnrecordedObservations);
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
        Assert.Equal(2, log.UnrecordedObservations);
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

        // The reload now happens off the trace thread, so it is awaited rather than raced. Waiting on
        // a background refresh with a sleep would test the scheduler, not the behaviour.
        await observer.RefreshRuledAsync();
        observer.OnConnection(Connection(@"C:\apps\a.exe", "1.2.3.4", 443));

        Assert.Empty(log.Snapshot());
    }

    /// <summary>
    /// The property the whole refactor exists for: a real-time ETW session drops events when its
    /// consumer is slow, so the callback must never touch the disk — not even once per refresh
    /// interval, which is what it used to do via <c>LoadOrAuditAsync().GetAwaiter().GetResult()</c>.
    /// </summary>
    [Fact]
    public async Task OnConnection_NeverBlocksOnTheStore_EvenWhenTheSnapshotIsStale()
    {
        var log = new PendingOutboundLog();
        var time = new TestClock(new DateTimeOffset(2026, 7, 16, 12, 0, 0, TimeSpan.Zero));
        // A store rooted at a path that cannot be read quickly would previously have stalled the
        // trace thread; here the only thing that matters is that the call returns without waiting.
        var observer = Observer(log, new FirewallPolicyStore(PolicyPath), time);

        // Force the snapshot stale so the refresh branch is taken on every one of these calls.
        time.Advance(TimeSpan.FromMinutes(1));
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        for (var i = 0; i < 200; i++)
        {
            time.Advance(TimeSpan.FromMinutes(1));
            observer.OnConnection(Connection($@"C:\apps\a{i}.exe", "1.2.3.4", 443));
        }
        stopwatch.Stop();

        Assert.True(
            stopwatch.Elapsed < TimeSpan.FromSeconds(2),
            $"200 stale-snapshot connections took {stopwatch.Elapsed}, which means the trace callback "
            + "is waiting on the policy store again.");

        // What the service itself waits for on stop: a background read must not outlive its owner,
        // and leaving one running here would have it racing this class's own directory cleanup.
        await observer.PendingRefresh;
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

    [Fact]
    public async Task AComWatcherFailureLogsOnlyTheFixedUnavailableTokenAndDoesNotFaultTheObserver()
    {
        var watcher = new ThrowingWatcher(EtwComFailure(unchecked((int)0x800705AA)));
        var logger = new CapturingLogger<OutboundObserverService>();
        var pending = new PendingOutboundLog();
        var observer = Observer(pending, watcher: watcher, logger: logger);

        await observer.StartAsync(CancellationToken.None);
        Assert.True(watcher.Called.Wait(TimeSpan.FromSeconds(5)));
        Assert.True(SpinWait.SpinUntil(() => !logger.Entries.IsEmpty, TimeSpan.FromSeconds(5)));
        await observer.StopAsync(CancellationToken.None);

        var unavailable = Assert.Single(logger.Entries, entry =>
            entry.Message.Contains("[FW_OBSERVER_UNAVAILABLE]", StringComparison.Ordinal));
        Assert.Null(unavailable.Exception);
        Assert.DoesNotContain("native ETW detail", unavailable.Message, StringComparison.Ordinal);
        Assert.Equal(1, pending.UnrecordedObservations);
    }

    [Fact]
    public async Task AnUnexpectedWatcherReturnLogsTheSameSingleUnavailableToken()
    {
        var watcher = new ReturningWatcher(waitForCancellation: false);
        var logger = new CapturingLogger<OutboundObserverService>();
        var pending = new PendingOutboundLog();
        var observer = Observer(pending, watcher: watcher, logger: logger);

        await observer.StartAsync(CancellationToken.None);
        Assert.True(watcher.Returned.Wait(TimeSpan.FromSeconds(5)));
        Assert.True(SpinWait.SpinUntil(() => logger.Entries.Any(entry =>
            entry.Message.Contains("[FW_OBSERVER_UNAVAILABLE]", StringComparison.Ordinal)), TimeSpan.FromSeconds(5)));
        await observer.StopAsync(CancellationToken.None);

        var unavailable = Assert.Single(logger.Entries, entry =>
            entry.Message.Contains("[FW_OBSERVER_UNAVAILABLE]", StringComparison.Ordinal));
        Assert.Null(unavailable.Exception);
        Assert.Equal(1, pending.UnrecordedObservations);
    }

    [Fact]
    public async Task AWatcherReturnAfterRequestedCancellationIsSilent()
    {
        var watcher = new ReturningWatcher(waitForCancellation: true);
        var logger = new CapturingLogger<OutboundObserverService>();
        var observer = Observer(new PendingOutboundLog(), watcher: watcher, logger: logger);

        await observer.StartAsync(CancellationToken.None);
        Assert.True(watcher.Started.Wait(TimeSpan.FromSeconds(5)));
        await observer.StopAsync(CancellationToken.None);
        Assert.True(watcher.Returned.Wait(TimeSpan.FromSeconds(5)));

        Assert.DoesNotContain(logger.Entries, entry =>
            entry.Message.Contains("[FW_OBSERVER_UNAVAILABLE]", StringComparison.Ordinal));
    }

    private static OutboundConnectionEvent Connection(string path, string address, int port) =>
        new(4242, path, address, port);

    private OutboundObserverService Observer(
        PendingOutboundLog log,
        FirewallPolicyStore? store = null,
        TimeProvider? time = null,
        IOutboundConnectionWatcher? watcher = null,
        ILogger<OutboundObserverService>? logger = null)
    {
        var observer = new OutboundObserverService(
            watcher ?? new OutboundConnectionWatcher(), store ?? new FirewallPolicyStore(PolicyPath), log,
            logger ?? NullLogger<OutboundObserverService>.Instance, time);
        _observers.Add(observer);
        return observer;
    }

    private sealed class ThrowingWatcher(Exception failure) : IOutboundConnectionWatcher
    {
        public ManualResetEventSlim Called { get; } = new();

        public void Watch(
            Action<OutboundConnectionEvent> onEvent,
            Action<int, string?>? onUnattributed,
            CancellationToken token)
        {
            Called.Set();
            throw failure;
        }
    }

    private sealed class ReturningWatcher(bool waitForCancellation) : IOutboundConnectionWatcher
    {
        public ManualResetEventSlim Started { get; } = new();

        public ManualResetEventSlim Returned { get; } = new();

        public void Watch(
            Action<OutboundConnectionEvent> onEvent,
            Action<int, string?>? onUnattributed,
            CancellationToken token)
        {
            Started.Set();
            if (waitForCancellation)
            {
                token.WaitHandle.WaitOne();
            }

            Returned.Set();
        }
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public ConcurrentQueue<(LogLevel Level, string Message, Exception? Exception)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Entries.Enqueue((logLevel, formatter(state, exception), exception));
        }
    }

    private static System.Runtime.InteropServices.COMException EtwComFailure(int hresult)
    {
        try
        {
            System.Runtime.InteropServices.Marshal.ThrowExceptionForHR(hresult);
        }
        catch (System.Runtime.InteropServices.COMException failure)
        {
            return failure;
        }

        throw new InvalidOperationException($"HRESULT 0x{hresult:X8} did not produce a COM exception.");
    }

    // TimeProvider is in the BCL and abstract, so controlling the clock costs a few lines rather
    // than a test-only package.
    private sealed class TestClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan delta) => _now += delta;
    }

    /// <summary>
    /// Waits for every background policy reload before deleting the store, exactly as the service's
    /// own <c>StopAsync</c> does.
    /// </summary>
    /// <remarks>
    /// Not defensive tidying: a reload started by the last observed connection was still holding
    /// <c>policies.json</c> open when this deleted the directory, and the resulting IOException
    /// surfaced against whichever unrelated test happened to run last. It reproduced on
    /// `windows-2022` and Arm64 while passing on the faster `windows-2025` image — the shape of a
    /// race, not of a broken assertion.
    /// </remarks>
    public async Task DisposeAsync()
    {
        foreach (var observer in _observers)
        {
            await observer.PendingRefresh;
        }

        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}
