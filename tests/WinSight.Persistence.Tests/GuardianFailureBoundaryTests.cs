using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// Failures on Guardian's timer threads, and shutdown while an acquisition ignores cancellation.
/// An unhandled exception in these paths ends the test host, so a passing run is itself evidence
/// that the failure stayed inside the monitor.
/// </summary>
public sealed class GuardianFailureBoundaryTests
{
    private static readonly TimeSpan[] FastRetries =
        [TimeSpan.FromMilliseconds(10), TimeSpan.FromMilliseconds(10), TimeSpan.FromMilliseconds(10)];

    private static AutostartEntry Entry(string name = "Updater") =>
        Entries.Unsigned(AutostartVector.RunKey, name, $@"C:\{name}.exe") with
        {
            Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run [Registry64]",
            Source = "Run keys",
        };

    private static PersistenceScanResult Scan(params AutostartEntry[] entries) =>
        new(entries, PersistenceCoverage.Complete, new HashSet<string> { "Run keys" });

    private static PersistenceMonitor Monitor(
        SignalSource source,
        Func<IReadOnlyList<IAutostartEnumerator>, CancellationToken, PersistenceScanResult> scan,
        IPersistenceBaselineStore? store = null,
        TimeSpan? disposeWait = null,
        IReadOnlyList<TimeSpan>? retries = null) =>
        new([], source, scan, core: null, debounce: TimeSpan.FromMilliseconds(1), clock: null,
            baselineStore: store ?? new MemoryStore(), disposeWait, retries ?? FastRetries);

    private static bool Eventually(Func<bool> condition) =>
        SpinWait.SpinUntil(condition, TimeSpan.FromSeconds(30));

    [Fact]
    public void ASubscriberFailingDuringMonitoringIsContainedVisibleAndRetriedUntilDelivered()
    {
        var entry = Entry();
        var store = new MemoryStore();
        var source = new SignalSource();
        var scans = 0;
        using var monitor = Monitor(source, (_, _) => Interlocked.Increment(ref scans) == 1 ? Scan() : Scan(entry), store);
        var calls = 0;
        monitor.Detected += (_, _) =>
        {
            if (Interlocked.Increment(ref calls) <= 2)
            {
                throw new InvalidOperationException("journal temporarily unavailable");
            }
        };
        monitor.Start();

        source.Signal();

        Assert.True(Eventually(() => monitor.Diagnostics.PendingNotifications == 0 && calls == 3));
        var diagnostics = monitor.Diagnostics;
        Assert.Equal(2, diagnostics.NotificationFailures);
        Assert.Equal(PersistenceMonitorOperation.Notification, diagnostics.LastFault!.Operation);
        Assert.IsType<InvalidOperationException>(diagnostics.LastFault.Exception);
        Assert.True(Eventually(() => store.Load()!.Contains(PersistenceIdentity.FromEntry(entry))));
    }

    [Fact]
    public void APersistentSubscriberFailureStopsAfterBoundedAttemptsAndIsNeverAcknowledged()
    {
        var entry = Entry();
        var store = new MemoryStore();
        var source = new SignalSource();
        var scans = 0;
        using var monitor = Monitor(source, (_, _) => Interlocked.Increment(ref scans) == 1 ? Scan() : Scan(entry), store);
        var calls = 0;
        monitor.Detected += (_, _) =>
        {
            Interlocked.Increment(ref calls);
            throw new InvalidOperationException("always fails");
        };
        monitor.Start();

        source.Signal();

        Assert.True(Eventually(() => monitor.Diagnostics.AutomaticRetriesExhausted));
        Thread.Sleep(200); // no hidden retry loop keeps running
        Assert.Equal(PersistenceMonitor.MaxDeliveryAttempts, calls);
        Assert.Equal(1, monitor.Diagnostics.PendingNotifications);
        Assert.True(monitor.Diagnostics.IsDegraded);
        Assert.DoesNotContain(PersistenceIdentity.FromEntry(entry), store.Load()!);

        monitor.RetryNow();
        Assert.True(Eventually(() => calls > PersistenceMonitor.MaxDeliveryAttempts));
    }

    [Fact]
    public void OneFailingSubscriberDoesNotBlockOrDuplicateAnotherSubscriber()
    {
        var entry = Entry();
        var source = new SignalSource();
        var scans = 0;
        using var monitor = Monitor(source, (_, _) => Interlocked.Increment(ref scans) == 1 ? Scan() : Scan(entry));
        var failing = 0;
        var healthy = 0;
        monitor.Detected += (_, _) =>
        {
            if (Interlocked.Increment(ref failing) == 1)
            {
                throw new InvalidOperationException("first attempt fails");
            }
        };
        monitor.Detected += (_, _) => Interlocked.Increment(ref healthy);
        monitor.Start();

        source.Signal();

        Assert.True(Eventually(() => monitor.Diagnostics.PendingNotifications == 0 && failing == 2));
        Assert.Equal(1, healthy);
    }

    [Fact]
    public void AnUnexpectedScanFailureIsContainedAndTheSameSurfacesAreScannedAgain()
    {
        var entry = Entry();
        var source = new SignalSource();
        var scans = 0;
        using var monitor = Monitor(source, (_, _) => Interlocked.Increment(ref scans) switch
        {
            1 => Scan(),
            2 => throw new System.Management.ManagementException("provider failed"),
            _ => Scan(entry),
        });
        var arrivals = 0;
        monitor.Detected += (_, _) => Interlocked.Increment(ref arrivals);
        monitor.Start();

        source.Signal(); // no second change signal: the retry alone must rescan

        // The arrival leaves the pending queue only after every subscriber has had it, so the count
        // alone can be read while the monitor still (truthfully) reports a delivery in progress.
        Assert.True(Eventually(() => arrivals == 1 && monitor.Diagnostics.PendingNotifications == 0));
        Assert.Equal(1, monitor.Diagnostics.ScanFailures);
        Assert.False(monitor.Diagnostics.IsDegraded);
    }

    [Fact]
    public void ABaselineSaveFailureIsVisibleAndRetried()
    {
        var entry = Entry();
        var store = new MemoryStore { FailuresBeforeSuccess = 2, FailOnlyWhenContaining = PersistenceIdentity.FromEntry(entry) };
        var source = new SignalSource();
        var scans = 0;
        using var monitor = Monitor(source, (_, _) => Interlocked.Increment(ref scans) == 1 ? Scan() : Scan(entry), store);
        monitor.Start();

        source.Signal();

        Assert.True(Eventually(() => store.Load()!.Contains(PersistenceIdentity.FromEntry(entry))));
        Assert.True(monitor.Diagnostics.SaveFailures >= 2);
        Assert.True(Eventually(() => !monitor.Diagnostics.IsDegraded));
    }

    [Fact]
    public void CatastrophicFailuresAreNotClassifiedAsRecoverable()
    {
#pragma warning disable CA2201 // classification only; never thrown
        Assert.True(PersistenceMonitor.IsCatastrophic(new OutOfMemoryException()));
#pragma warning restore CA2201
        Assert.True(PersistenceMonitor.IsCatastrophic(new InsufficientExecutionStackException()));
        Assert.False(PersistenceMonitor.IsCatastrophic(new InvalidOperationException()));
        Assert.False(PersistenceMonitor.IsCatastrophic(new IOException()));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task DisposeReturnsDuringANonCooperativeReadAndFinishesShutdownWhenTheReadEnds(bool duringStartup)
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var source = new SignalSource();
        var store = new MemoryStore();
        var scans = 0;
        var entry = Entry();
        var monitor = Monitor(source, (_, _) =>
        {
            if (duringStartup || Interlocked.Increment(ref scans) > 1)
            {
                entered.Set();
                release.Wait(CancellationToken.None); // ignores the cancellation token, like a blocked native read
                return Scan(entry);
            }
            return Scan();
        }, store, disposeWait: TimeSpan.FromMilliseconds(50));
        var afterDispose = 0;
        var disposedFlag = 0;
        monitor.Detected += (_, _) =>
        {
            if (Volatile.Read(ref disposedFlag) == 1)
            {
                Interlocked.Increment(ref afterDispose);
            }
        };
        var starting = Task.Run(() => monitor.Start());
        if (!duringStartup)
        {
            await starting.WaitAsync(TimeSpan.FromSeconds(30));
            source.Signal();
        }
        Assert.True(entered.Wait(TimeSpan.FromSeconds(30)));

        await Task.Run(() =>
        {
            Volatile.Write(ref disposedFlag, 1);
            monitor.Dispose();
        }).WaitAsync(TimeSpan.FromSeconds(30));

        Assert.False(source.Disposed); // still in use by the blocked read: not released early
        Assert.True(monitor.Diagnostics.ShutdownDeferred);

        release.Set();
        await starting.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.True(Eventually(() => source.Disposed));
        Assert.False(monitor.Diagnostics.ShutdownDeferred);
        Assert.Equal(0, afterDispose);
        Assert.Equal(1, source.DisposeCount);
        // The entry read after shutdown began was never reported, so it must not be acknowledged.
        Assert.DoesNotContain(PersistenceIdentity.FromEntry(entry), store.Load() ?? new HashSet<PersistenceIdentity>());
    }

    [Fact]
    public async Task ConcurrentStartAndDisposeNeverDeadlockOrReleaseTheSourceTwice()
    {
        for (var iteration = 0; iteration < 40; iteration++)
        {
            var source = new SignalSource();
            var store = new MemoryStore();
            var monitor = Monitor(source, (_, token) =>
            {
                Thread.SpinWait(iteration * 50);
                return Scan(Entry());
            }, store, disposeWait: TimeSpan.FromMilliseconds(20));
            var start = Task.Run(() =>
            {
                try
                {
                    monitor.Start();
                }
                catch (OperationCanceledException)
                {
                    // Dispose won before the scan began.
                }
            });
            var dispose = Task.Run(monitor.Dispose);
            await Task.WhenAll(start, dispose).WaitAsync(TimeSpan.FromSeconds(30));
            Assert.True(Eventually(() => source.Disposed));
            Assert.Equal(1, source.DisposeCount);
            Assert.False(monitor.IsStarted);
        }
    }

    private sealed class SignalSource : IPersistenceChangeSource
    {
        private int _disposeCount;
        public bool Disposed => DisposeCount > 0;
        public int DisposeCount => Volatile.Read(ref _disposeCount);
        public event EventHandler<PersistenceSurfaceChangedEventArgs>? SurfaceChanged;
        public void Signal() => SurfaceChanged?.Invoke(this, new PersistenceSurfaceChangedEventArgs([]));
        public void Start()
        {
        }
        public void Dispose() => Interlocked.Increment(ref _disposeCount);
    }

    private sealed class MemoryStore : IPersistenceBaselineStore
    {
        private readonly Lock _gate = new();
        private IReadOnlySet<PersistenceIdentity>? _baseline;
        public int FailuresBeforeSuccess { get; set; }
        public PersistenceIdentity? FailOnlyWhenContaining { get; set; }

        public IReadOnlySet<PersistenceIdentity>? Load()
        {
            lock (_gate)
            {
                return _baseline;
            }
        }

        public void Save(IReadOnlyCollection<PersistenceIdentity> baseline)
        {
            lock (_gate)
            {
                if (FailuresBeforeSuccess > 0
                    && (FailOnlyWhenContaining is not { } required || baseline.Contains(required)))
                {
                    FailuresBeforeSuccess--;
                    throw new IOException("disk full");
                }
                _baseline = baseline.ToHashSet();
            }
        }
    }
}
