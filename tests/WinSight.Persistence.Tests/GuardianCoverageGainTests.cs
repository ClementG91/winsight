using WinSight.Core;
using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// WS-70. The persisted baseline remembered which identities it had seen but not which sources it
/// had been able to read. A baseline saved by an unelevated dashboard knows only the scheduled tasks
/// and services a standard user can read; the first elevated launch read the rest and announced every
/// one of them as a new startup item (about sixty on the qualification VM). What becomes readable
/// for the first time is a baseline, exactly like a first launch, never an arrival.
/// </summary>
public sealed class GuardianCoverageGainTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 23, 9, 0, 0, TimeSpan.Zero);
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

    /// <summary>A source read only in part, with no attributable scope: an unelevated task scan.</summary>
    private static PersistenceScanResult Unreadable(string source, params AutostartEntry[] entries) =>
        new(entries, new PersistenceCoverage(1, [source]), new HashSet<string>());

    private static PersistenceScanResult Partial(string source, string[] unreadableScopes, params AutostartEntry[] entries) =>
        new(entries, new PersistenceCoverage(1, [source]), new HashSet<string>())
        {
            PartialSources = new Dictionary<string, IReadOnlyCollection<string>> { [source] = unreadableScopes },
        };

    private static HashSet<PersistenceIdentity> Ids(params AutostartEntry[] entries) =>
        entries.Select(PersistenceIdentity.FromEntry).ToHashSet();

    [Fact]
    public void WhatAnElevatedLaunchCanReadForTheFirstTimeIsBaselinedNotAnnounced()
    {
        var readable = Task("Updater");
        var protectedOne = Task("Defrag");
        var protectedTwo = Task("Maintenance");
        var core = new PersistenceMonitorCore();

        // Saved by an unelevated run: the task source was not readable in full.
        var saved = PersistenceCoverageMap.FromScan(Unreadable(Tasks, readable));
        var detected = core.ReconcileFromPersistedBaseline(
            Ids(readable), saved, Complete(Tasks, readable, protectedOne, protectedTwo), T0);

        Assert.Empty(detected);
        Assert.Equal(Ids(readable, protectedOne, protectedTwo), core.CurrentBaseline.ToHashSet());
        Assert.Equal(2, core.AbsorbedOnCoverageGain);
        Assert.True(core.CurrentCoverage!.Covers(Tasks, protectedOne.Location));
    }

    [Fact]
    public void ANewEntryInASourceTheBaselineAlreadyCoveredIsStillAnnounced()
    {
        var known = Task("Updater");
        var planted = Task("Planted");
        var core = new PersistenceMonitorCore();

        var saved = PersistenceCoverageMap.FromScan(Complete(Tasks, known));
        var detected = core.ReconcileFromPersistedBaseline(Ids(known), saved, Complete(Tasks, known, planted), T0);

        Assert.Equal("Planted", Assert.Single(detected).Entry.Name);
        Assert.Equal(0, core.AbsorbedOnCoverageGain);
    }

    [Fact]
    public void ABaselineSavedWithoutCoverageKeepsAnnouncingAsBefore()
    {
        // The upgrade path: a v0.13 file has no coverage. Absorbing everything on its first read would
        // silence whatever arrived while WinSight was off, so the old behaviour stands for that read.
        var known = Task("Updater");
        var newcomer = Task("Newcomer");
        var core = new PersistenceMonitorCore();

        var detected = core.ReconcileFromPersistedBaseline(Ids(known), persistedCoverage: null, Complete(Tasks, known, newcomer), T0);

        Assert.Single(detected);
        Assert.NotNull(core.CurrentCoverage);
    }

    [Fact]
    public void CoverageIsKeptThroughAnUnelevatedRunSoALaterArrivalIsNotLost()
    {
        var known = Task("Updater");
        var planted = Task("Planted");
        var core = new PersistenceMonitorCore();
        core.SeedBaseline(Complete(Tasks, known));                                  // elevated

        Assert.Empty(core.Reconcile(Unreadable(Tasks), T0));                        // unelevated
        Assert.True(core.CurrentCoverage!.Covers(Tasks, known.Location));
        Assert.Contains(PersistenceIdentity.FromEntry(known), core.CurrentBaseline);

        // Planted while only the unelevated view was available: the next full view reports it.
        Assert.Equal("Planted", Assert.Single(core.Reconcile(Complete(Tasks, known, planted), T0.AddMinutes(1))).Entry.Name);
    }

    [Fact]
    public void APartlyReadableSourceAbsorbsOnlyTheScopesItCouldNotReadBefore()
    {
        var mine = Hive("S-1-5-21-1-1001", "Mine");
        var other = Hive("S-1-5-21-1-1002", "OtherUser");
        var planted = Hive("S-1-5-21-1-1001", "Planted");
        var core = new PersistenceMonitorCore();

        var saved = PersistenceCoverageMap.FromScan(Partial(Hives, [@"HKU\S-1-5-21-1-1002"], mine));
        var detected = core.ReconcileFromPersistedBaseline(Ids(mine), saved, Complete(Hives, mine, other, planted), T0);

        Assert.Equal("Planted", Assert.Single(detected).Entry.Name);
        Assert.Equal(1, core.AbsorbedOnCoverageGain);
    }

    [Fact]
    public void LiveRescansApplyTheSameRuleAfterAScanSeededBaseline()
    {
        var readable = Task("Updater");
        var protectedOne = Task("Defrag");
        var core = new PersistenceMonitorCore();
        core.SeedBaseline(Unreadable(Tasks, readable));

        Assert.Empty(core.Reconcile(Complete(Tasks, readable, protectedOne), T0));
        Assert.Equal(1, core.AbsorbedOnCoverageGain);
    }

    [Fact]
    public void AnEntrySeededBaselineHasNoCoverageAndKeepsTheOldRule()
    {
        var readable = Task("Updater");
        var newcomer = Task("Newcomer");
        var core = new PersistenceMonitorCore();
        core.SeedBaseline([readable]);

        Assert.Null(core.CurrentCoverage);
        Assert.Single(core.Reconcile(Complete(Tasks, readable, newcomer), T0));
    }

    [Fact]
    public void ASourceThatCannotConfirmAbsenceNeverCountsAsNewlyReadable()
    {
        // Such a source is never "complete", so its arrivals are always reported.
        var saved = PersistenceCoverageMap.FromScan(Unreadable("WMI subscriptions"));
        var fresh = Entries.Unsigned(AutostartVector.WmiSubscription, "Consumer", @"C:\x.exe") with
        {
            Location = @"root\subscription",
            Source = "WMI subscriptions",
        };
        var core = new PersistenceMonitorCore();

        var detected = core.ReconcileFromPersistedBaseline(
            new HashSet<PersistenceIdentity>(), saved, new PersistenceScanResult([fresh], PersistenceCoverage.Complete, new HashSet<string>()), T0);

        Assert.Single(detected);
    }

    [Theory]
    [InlineData(new[] { @"HKU\S-1", @"HKU\S-2" }, new[] { @"HKU\S-2\Software" }, new[] { @"HKU\S-2\Software" })]
    [InlineData(new[] { @"HKU\S-1" }, new[] { @"HKU\S-2" }, new string[0])]
    [InlineData(new[] { @"HKU\S-1" }, new[] { @"hku\s-1" }, new[] { @"hku\s-1" })]
    public void MergingKeepsUncoveredOnlyWhatNeitherViewCouldRead(string[] first, string[] second, string[] expected)
    {
        var merged = PersistenceCoverageMap.FromScan(Partial(Hives, first))
            .Merge(PersistenceCoverageMap.FromScan(Partial(Hives, second)));

        Assert.Equal(expected.Order(StringComparer.OrdinalIgnoreCase), merged.UncoveredScopes(Hives)!.Order(StringComparer.OrdinalIgnoreCase));
    }

    [Fact]
    public void CompleteWinsAMergeAndAnAbsentSourceStaysUncovered()
    {
        var merged = PersistenceCoverageMap.FromScan(Partial(Hives, [@"HKU\S-1"]))
            .Merge(PersistenceCoverageMap.FromScan(Complete(Hives)));

        Assert.True(merged.Covers(Hives, @"HKU\S-1\Software"));
        Assert.False(merged.Covers(Tasks, @"C:\Windows\System32\Tasks\X"));
        Assert.Null(merged.UncoveredScopes(Tasks));
    }
}

public sealed class GuardianCoveragePersistenceTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "winsight-coverage-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private string NewPath()
    {
        Directory.CreateDirectory(_directory);
        return Path.Combine(_directory, "guardian-baseline.tsv");
    }

    private static readonly string[] HiveScopes = [@"HKU\S-1-5-21-1-1002", "tab\tand\nnewline"];

    private static PersistenceIdentity Id(string name, string source) =>
        new(AutostartVector.ScheduledTask, name, $@"c:\{name}.exe", "", $@"c:\windows\system32\tasks\{name}", source);

    [Fact]
    public void CoverageRoundTripsWithTheBaseline()
    {
        var store = new FilePersistenceBaselineStore(NewPath());
        var coverage = new PersistenceCoverageMap(new Dictionary<string, IReadOnlyList<string>>
        {
            ["Scheduled Tasks"] = [],
            ["Other user hives"] = HiveScopes,
        });

        store.Save([Id("a", "Scheduled Tasks")], coverage);
        var loaded = store.LoadWithCoverage();

        Assert.NotNull(loaded);
        Assert.Equal(new[] { Id("a", "Scheduled Tasks") }, loaded.Identities);
        Assert.True(loaded.Coverage!.Covers("Scheduled Tasks", @"c:\anything"));
        Assert.Equal(HiveScopes, loaded.Coverage.UncoveredScopes("Other user hives"));
    }

    [Fact]
    public void AnEmptyBaselineWithCoverageIsStillABaseline()
    {
        var store = new FilePersistenceBaselineStore(NewPath());

        store.Save([], PersistenceCoverageMap.Empty);
        var loaded = store.LoadWithCoverage();

        Assert.NotNull(loaded);
        Assert.Empty(loaded.Identities);
        Assert.NotNull(loaded.Coverage);
    }

    [Fact]
    public void ABaselineWrittenWithoutCoverageLoadsWithUnknownCoverage()
    {
        var store = new FilePersistenceBaselineStore(NewPath());

        store.Save([Id("a", "Scheduled Tasks")]);
        var loaded = store.LoadWithCoverage();

        Assert.NotNull(loaded);
        Assert.Single(loaded.Identities);
        Assert.Null(loaded.Coverage);
    }

    [Fact]
    public void TheIdentityOnlyReaderIgnoresCoverageLines()
    {
        // What a v0.13 dashboard sees after a downgrade: its reader skips lines that are not six
        // fields, so the coverage lines must never be mistaken for identities, nor break the load.
        var path = NewPath();
        var store = new FilePersistenceBaselineStore(path);
        store.Save([Id("a", "Scheduled Tasks")], PersistenceCoverageMap.FromScan(
            new PersistenceScanResult([], PersistenceCoverage.Complete, new HashSet<string> { "Scheduled Tasks" })));

        Assert.All(File.ReadAllLines(path).Where(line => line.StartsWith('@')), line => Assert.NotEqual(6, line.Split('\t').Length));
        Assert.Equal(new[] { Id("a", "Scheduled Tasks") }, store.Load());
    }
}

public sealed class GuardianCoverageMonitorTests
{
    [Fact]
    public void AnElevatedStartupAfterAnUnelevatedSaveRaisesNothingAndSavesTheWiderCoverage()
    {
        var readable = Entries.Signed(AutostartVector.ScheduledTask, "Updater", @"C:\u.exe") with
        {
            Location = @"C:\Windows\System32\Tasks\Updater",
            Source = "Scheduled Tasks",
        };
        var hidden = readable with { Name = "Defrag", Location = @"C:\Windows\System32\Tasks\Defrag" };
        var store = new CoverageStore(
            new HashSet<PersistenceIdentity> { PersistenceIdentity.FromEntry(readable) },
            PersistenceCoverageMap.FromScan(new PersistenceScanResult(
                [readable], new PersistenceCoverage(1, ["Scheduled Tasks"]), new HashSet<string>())));
        var raised = 0;
        using var monitor = new PersistenceMonitor([], new SilentSource(), (_, _) =>
            new PersistenceScanResult([readable, hidden], PersistenceCoverage.Complete, new HashSet<string> { "Scheduled Tasks" }),
            baselineStore: store);
        monitor.Detected += (_, _) => Interlocked.Increment(ref raised);

        monitor.Start();

        Assert.Equal(0, raised);
        Assert.Equal(2, store.Saved.Count);
        Assert.True(store.SavedCoverage!.Covers("Scheduled Tasks", hidden.Location));
    }

    private sealed class CoverageStore(IReadOnlySet<PersistenceIdentity> identities, PersistenceCoverageMap coverage)
        : IPersistenceBaselineStore
    {
        public IReadOnlyCollection<PersistenceIdentity> Saved { get; private set; } = [];
        public PersistenceCoverageMap? SavedCoverage { get; private set; }
        public IReadOnlySet<PersistenceIdentity> Load() => identities;
        public PersistedBaseline LoadWithCoverage() => new(identities, coverage);
        public void Save(IReadOnlyCollection<PersistenceIdentity> baseline) => Saved = baseline;
        public void Save(IReadOnlyCollection<PersistenceIdentity> baseline, PersistenceCoverageMap? coverage)
        {
            Saved = baseline;
            SavedCoverage = coverage;
        }
    }

    private sealed class SilentSource : IPersistenceChangeSource
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
