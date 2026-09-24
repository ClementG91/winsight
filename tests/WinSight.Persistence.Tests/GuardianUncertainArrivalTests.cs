using WinSight.Core;

using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// RA-03. WS-70 baselines what becomes readable for the first time instead of announcing it, which
/// is right for the sixty scheduled tasks Windows ships and wrong to do in silence: an entry planted
/// while its location was unreadable looks exactly like one that was always there. The absorbed
/// entries are now handed on as one uncertain batch - counted, located, never called an arrival.
/// </summary>
public sealed class GuardianUncertainArrivalTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 24, 9, 0, 0, TimeSpan.Zero);
    private const string Tasks = "Scheduled Tasks";
    private const string Hives = "Other user hives";

    private static AutostartEntry Task(string name) =>
        Entries.Signed(AutostartVector.ScheduledTask, name, $@"C:\Windows\System32\{name}.exe") with
        {
            Location = $@"C:\Windows\System32\Tasks\{name}",
            Source = Tasks,
        };

    private static AutostartEntry Hive(string sid, string name) =>
        Entries.Unsigned(AutostartVector.RunKey, name, $@"C:\{name}.exe") with
        {
            Location = $@"HKU\{sid}\Software\Microsoft\Windows\CurrentVersion\Run [Registry64]",
            Source = Hives,
        };

    private static PersistenceScanResult Complete(string source, params AutostartEntry[] entries) =>
        new(entries, PersistenceCoverage.Complete, new HashSet<string> { source });

    private static PersistenceScanResult Unreadable(string source, params AutostartEntry[] entries) =>
        new(entries, new PersistenceCoverage(1, [source]), new HashSet<string>());

    private static HashSet<PersistenceIdentity> Ids(params AutostartEntry[] entries) =>
        entries.Select(PersistenceIdentity.FromEntry).ToHashSet();

    [Fact]
    public void APersistedBaselineHandsOnWhatItAbsorbedOnceWithItsSources()
    {
        var readable = Task("Updater");
        var defrag = Task("Defrag");
        var planted = Task("Planted");
        var core = new PersistenceMonitorCore();

        var detected = core.ReconcileFromPersistedBaseline(
            Ids(readable), PersistenceCoverageMap.FromScan(Unreadable(Tasks, readable)),
            Complete(Tasks, readable, defrag, planted), T0);

        Assert.Empty(detected);
        var gain = core.TakeCoverageGain();
        Assert.NotNull(gain);
        Assert.Equal(2, gain.Count);
        Assert.Equal("Defrag,Planted", string.Join(',', gain.Entries.Select(entry => entry.Name).Order()));
        Assert.Equal(Tasks, Assert.Single(gain.Sources));
        Assert.Equal(T0, gain.ObservedUtc);
        Assert.Null(core.TakeCoverageGain());
    }

    [Fact]
    public void ALiveRescanHandsOnWhatItAbsorbed()
    {
        var readable = Task("Updater");
        var hidden = Task("Defrag");
        var core = new PersistenceMonitorCore();
        core.SeedBaseline(Unreadable(Tasks, readable));

        Assert.Empty(core.Reconcile(Complete(Tasks, readable, hidden), T0));

        Assert.Equal("Defrag", Assert.Single(core.TakeCoverageGain()!.Entries).Name);
    }

    [Fact]
    public void AGenuinelyCoveredLocationStillProducesAnArrivalAndNoUncertainty()
    {
        var known = Task("Updater");
        var planted = Task("Planted");
        var core = new PersistenceMonitorCore();

        var detected = core.ReconcileFromPersistedBaseline(
            Ids(known), PersistenceCoverageMap.FromScan(Complete(Tasks, known)), Complete(Tasks, known, planted), T0);

        Assert.Equal("Planted", Assert.Single(detected).Entry.Name);
        Assert.Null(core.TakeCoverageGain());
    }

    [Fact]
    public void AnOlderBaselineWithoutCoverageAnnouncesEverythingAndAbsorbsNothing()
    {
        var known = Task("Updater");
        var newcomer = Task("Newcomer");
        var core = new PersistenceMonitorCore();

        var detected = core.ReconcileFromPersistedBaseline(
            Ids(known), persistedCoverage: null, Complete(Tasks, known, newcomer), T0);

        Assert.Single(detected);
        Assert.Null(core.TakeCoverageGain());
    }

    [Fact]
    public void OnlyTheScopeThatWasUnreadableIsUncertain()
    {
        var mine = Hive("S-1-5-21-1-1001", "Mine");
        var other = Hive("S-1-5-21-1-1002", "OtherUser");
        var planted = Hive("S-1-5-21-1-1001", "Planted");
        var core = new PersistenceMonitorCore();
        var saved = PersistenceCoverageMap.FromScan(new PersistenceScanResult(
            [mine], new PersistenceCoverage(1, [Hives]), new HashSet<string>())
        {
            PartialSources = new Dictionary<string, IReadOnlyCollection<string>> { [Hives] = [@"HKU\S-1-5-21-1-1002"] },
        });

        var detected = core.ReconcileFromPersistedBaseline(Ids(mine), saved, Complete(Hives, mine, other, planted), T0);

        Assert.Equal("Planted", Assert.Single(detected).Entry.Name);
        Assert.Equal("OtherUser", Assert.Single(core.TakeCoverageGain()!.Entries).Name);
    }

    [Fact]
    public void AnUnreadableIntervalFollowedByAWiderViewIsReportedNotHidden()
    {
        // Elevated seed, unelevated stretch, then a planted task becomes visible when the view widens
        // again. It was planted where the baseline had full coverage, so it is an arrival - not merely
        // uncertain - because coverage survives the unelevated stretch.
        var known = Task("Updater");
        var planted = Task("Planted");
        var core = new PersistenceMonitorCore();
        core.SeedBaseline(Complete(Tasks, known));
        Assert.Empty(core.Reconcile(Unreadable(Tasks), T0));

        var detected = core.Reconcile(Complete(Tasks, known, planted), T0.AddMinutes(5));

        Assert.Equal("Planted", Assert.Single(detected).Entry.Name);
        Assert.Null(core.TakeCoverageGain());
    }

    [Fact]
    public void AVeryLargeGainIsCountedInFullAndListedWithinItsBound()
    {
        var readable = Task("Updater");
        var hidden = Enumerable.Range(0, PersistenceCoverageGain.MaxListed + 3).Select(i => Task($"T{i}")).ToArray();
        var core = new PersistenceMonitorCore();
        core.SeedBaseline(Unreadable(Tasks, readable));

        core.Reconcile(Complete(Tasks, [readable, .. hidden]), T0);

        var gain = core.TakeCoverageGain()!;
        Assert.Equal(hidden.Length, gain.Count);
        Assert.Equal(PersistenceCoverageGain.MaxListed, gain.Entries.Count);
        Assert.Equal(3, gain.Unlisted);
    }
}

public sealed class GuardianUncertainArrivalMonitorTests
{
    private const string Tasks = "Scheduled Tasks";

    private static readonly AutostartEntry Readable = Entries.Signed(AutostartVector.ScheduledTask, "Updater", @"C:\u.exe") with
    {
        Location = @"C:\Windows\System32\Tasks\Updater",
        Source = Tasks,
    };

    private static readonly AutostartEntry Hidden = Readable with { Name = "Defrag", Location = @"C:\Windows\System32\Tasks\Defrag" };

    private static PersistenceScanResult ElevatedScan(IReadOnlyList<IAutostartEnumerator> surfaces, CancellationToken token) =>
        new([Readable, Hidden], PersistenceCoverage.Complete, new HashSet<string> { Tasks });

    private static MemoryCoverageStore UnelevatedSave() => new(
        new HashSet<PersistenceIdentity> { PersistenceIdentity.FromEntry(Readable) },
        PersistenceCoverageMap.FromScan(new PersistenceScanResult(
            [Readable], new PersistenceCoverage(1, [Tasks]), new HashSet<string>())));

    [Fact]
    public void TheStartupGainIsDeliveredAsUncertainAndThenSaved()
    {
        var store = UnelevatedSave();
        var gains = new List<PersistenceCoverageGain>();
        var arrivals = 0;
        using var monitor = new PersistenceMonitor([], new QuietSource(), ElevatedScan, baselineStore: store);
        monitor.CoverageGained += (_, e) => gains.Add(e.Gain);
        monitor.Detected += (_, _) => Interlocked.Increment(ref arrivals);

        monitor.Start();

        Assert.Equal(0, arrivals);
        Assert.Equal("Defrag", Assert.Single(Assert.Single(gains).Entries).Name);
        Assert.Equal(1, monitor.Diagnostics.CoverageGainEntries);
        Assert.Equal(0, monitor.Diagnostics.PendingCoverageGains);
        Assert.Contains(PersistenceIdentity.FromEntry(Hidden), store.Identities);
    }

    // At-least-once, like an arrival: a notice nobody could record keeps its entries out of the saved
    // baseline, and because their location is covered by then, the next launch announces them.
    [Fact]
    public void AnUndeliveredGainIsNeverSilentlyKnownOnTheNextLaunch()
    {
        var store = UnelevatedSave();
        using (var first = new PersistenceMonitor([], new QuietSource(), ElevatedScan, baselineStore: store))
        {
            first.CoverageGained += (_, _) => throw new IOException("journal unwritable");
            first.Start();

            Assert.Equal(1, first.Diagnostics.PendingCoverageGains);
            Assert.DoesNotContain(PersistenceIdentity.FromEntry(Hidden), store.Identities);
            Assert.True(store.Coverage!.Covers(Tasks, Hidden.Location));
        }

        var arrivals = new List<PersistenceEvent>();
        using var next = new PersistenceMonitor([], new QuietSource(), ElevatedScan, baselineStore: store);
        next.Detected += (_, e) => arrivals.Add(e.Detected);
        next.Start();

        Assert.Equal("Defrag", Assert.Single(arrivals).Entry.Name);
    }

    private sealed class MemoryCoverageStore(IReadOnlySet<PersistenceIdentity> identities, PersistenceCoverageMap coverage)
        : IPersistenceBaselineStore
    {
        public IReadOnlySet<PersistenceIdentity> Identities { get; private set; } = identities;
        public PersistenceCoverageMap? Coverage { get; private set; } = coverage;
        public IReadOnlySet<PersistenceIdentity> Load() => Identities;
        public PersistedBaseline LoadWithCoverage() => new(Identities, Coverage);
        public void Save(IReadOnlyCollection<PersistenceIdentity> baseline) => Identities = baseline.ToHashSet();
        public void Save(IReadOnlyCollection<PersistenceIdentity> baseline, PersistenceCoverageMap? coverage)
        {
            Identities = baseline.ToHashSet();
            Coverage = coverage;
        }
    }

    private sealed class QuietSource : IPersistenceChangeSource
    {
        public event EventHandler<PersistenceSurfaceChangedEventArgs>? SurfaceChanged
        {
            add { }
            remove { }
        }
        public void Start() { }
        public void Dispose() { }
    }
}
