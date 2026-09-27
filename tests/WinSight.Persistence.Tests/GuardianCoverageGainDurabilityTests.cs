using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// RB-02: the bounded notice must not acknowledge its unlisted entries before delivery, including
/// through the real baseline format, shutdown, and a live retry without a new scan.
/// </summary>
public sealed class GuardianCoverageGainDurabilityTests
{
    private const string Tasks = "Scheduled Tasks";
    private static readonly AutostartEntry Readable = TaskEntry("Readable");

    private static AutostartEntry TaskEntry(string name) =>
        Entries.Signed(AutostartVector.ScheduledTask, name, @"C:\Windows\System32\task.exe") with
        {
            Location = $@"C:\Windows\System32\Tasks\{name}",
            Source = Tasks,
        };

    private static AutostartEntry[] HiddenEntries() =>
        Enumerable.Range(0, PersistenceCoverageGain.MaxListed + 2)
            .Select(index => TaskEntry($"Hidden{index}"))
            .ToArray();

    private static PersistenceScanResult UnreadableScan() =>
        new([Readable], new PersistenceCoverage(1, [Tasks]), new HashSet<string>());

    private static PersistenceScanResult CompleteScan(AutostartEntry[] hidden) =>
        new([Readable, .. hidden], PersistenceCoverage.Complete, new HashSet<string> { Tasks });

    private static PersistenceMonitor Monitor(
        SignalSource source,
        Func<IReadOnlyList<IAutostartEnumerator>, CancellationToken, PersistenceScanResult> scan,
        IPersistenceBaselineStore store,
        IReadOnlyList<TimeSpan>? retryDelays = null) =>
        new([], source, scan, core: null, debounce: TimeSpan.FromMilliseconds(1), clock: null,
            baselineStore: store, disposeWait: null, retryDelays: retryDelays ?? []);

    [Fact]
    public async Task ALiveOverflowGainRetainsTheDiskBaselineUntilEverySubscriberAcceptsIt()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wsg-gain-live-{Guid.NewGuid():N}.tsv");
        try
        {
            var hidden = HiddenEntries();
            var store = new FilePersistenceBaselineStore(path);
            var source = new SignalSource();
            var scans = 0;
            using var monitor = Monitor(source,
                (_, _) => Interlocked.Increment(ref scans) == 1 ? UnreadableScan() : CompleteScan(hidden),
                store, [TimeSpan.FromMilliseconds(10)]);
            var accepted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var healthyCalls = 0;
            var recoveringCalls = 0;
            var beforeAcceptance = new List<byte[]>();
            monitor.CoverageGained += (_, _) => Interlocked.Increment(ref healthyCalls);
            monitor.CoverageGained += (_, _) =>
            {
                // This observes the real file before both the failed and successful hand-off.
                beforeAcceptance.Add(File.ReadAllBytes(path));
                if (Interlocked.Increment(ref recoveringCalls) == 1)
                {
                    throw new IOException("journal temporarily unavailable");
                }
                accepted.TrySetResult();
            };
            monitor.Start();
            var previousFile = File.ReadAllBytes(path);

            source.Signal();

            await accepted.Task.WaitAsync(TimeSpan.FromSeconds(30));
            Assert.True(SpinWait.SpinUntil(() => !monitor.Diagnostics.IsDegraded, TimeSpan.FromSeconds(30)));
            Assert.Equal(2, scans); // notification recovery did not need another scan or change signal
            Assert.Equal(1, healthyCalls);
            Assert.Equal(2, recoveringCalls);
            Assert.Equal(2, beforeAcceptance.Count);
            Assert.All(beforeAcceptance, snapshot => Assert.Equal(previousFile, snapshot));
            Assert.Equal(1, monitor.Diagnostics.NotificationFailures);
            Assert.Equal(0, monitor.Diagnostics.PendingCoverageGains);
            var persisted = Assert.IsType<PersistedBaseline>(store.LoadWithCoverage());
            Assert.Equal(hidden.Length + 1, persisted.Identities.Count);
            Assert.All(hidden, entry => Assert.Contains(PersistenceIdentity.FromEntry(entry), persisted.Identities));
            Assert.True(persisted.Coverage!.Covers(Tasks, hidden[^1].Location));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void AnUndeliveredOverflowGainSurvivesTheRealFileAndShutdownSave()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wsg-gain-restart-{Guid.NewGuid():N}.tsv");
        try
        {
            var hidden = HiddenEntries();
            var store = new FilePersistenceBaselineStore(path);
            store.Save([PersistenceIdentity.FromEntry(Readable)], PersistenceCoverageMap.FromScan(UnreadableScan()));
            var previousFile = File.ReadAllBytes(path);
            using (var first = Monitor(new SignalSource(), (_, _) => CompleteScan(hidden), store))
            {
                first.CoverageGained += (_, _) => throw new IOException("journal unavailable until next launch");
                first.Start();

                Assert.Equal(1, first.Diagnostics.PendingCoverageGains);
                Assert.Equal(previousFile, File.ReadAllBytes(path));
            }
            Assert.Equal(previousFile, File.ReadAllBytes(path));

            var gains = new List<PersistenceCoverageGain>();
            var arrivals = new List<PersistenceEvent>();
            // A fresh store instance reads the on-disk state; no in-memory snapshot crosses launches.
            using (var next = Monitor(new SignalSource(), (_, _) => CompleteScan(hidden), new FilePersistenceBaselineStore(path)))
            {
                next.CoverageGained += (_, e) => gains.Add(e.Gain);
                next.Detected += (_, e) => arrivals.Add(e.Detected);
                next.Start();
                var repeated = Assert.Single(gains);
                Assert.Equal(hidden.Length, repeated.Count);
                Assert.Equal(2, repeated.Unlisted);
                Assert.Empty(arrivals);
            }

            var persisted = Assert.IsType<PersistedBaseline>(new FilePersistenceBaselineStore(path).LoadWithCoverage());
            Assert.Equal(hidden.Length + 1, persisted.Identities.Count);
            Assert.All(hidden, entry => Assert.Contains(PersistenceIdentity.FromEntry(entry), persisted.Identities));
            Assert.True(persisted.Coverage!.Covers(Tasks, hidden[^1].Location));
            using var afterAcknowledgement = Monitor(new SignalSource(), (_, _) => CompleteScan(hidden),
                new FilePersistenceBaselineStore(path));
            afterAcknowledgement.CoverageGained += (_, e) => gains.Add(e.Gain);
            afterAcknowledgement.Detected += (_, e) => arrivals.Add(e.Detected);
            afterAcknowledgement.Start();

            Assert.Single(gains);
            Assert.Empty(arrivals);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private sealed class SignalSource : IPersistenceChangeSource
    {
        public event EventHandler<PersistenceSurfaceChangedEventArgs>? SurfaceChanged;
        public void Signal() => SurfaceChanged?.Invoke(this, new PersistenceSurfaceChangedEventArgs([]));
        public void Start() { }
        public void Dispose() { }
    }
}
