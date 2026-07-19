using WinSight.Persistence;

using Xunit;

namespace WinSight.Persistence.Tests;

public sealed class PersistenceMonitorCoreReconciliationTests
{
    private static readonly DateTimeOffset T0 = new(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);

    private static HashSet<PersistenceIdentity> Ids(params AutostartEntry[] entries) =>
        entries.Select(PersistenceIdentity.FromEntry).ToHashSet();

    [Fact]
    public void ReconcileFromPersistedBaseline_SurfacesWhatAppearedWhileOff()
    {
        var core = new PersistenceMonitorCore();
        var persisted = Ids(Entries.Signed(AutostartVector.RunKey, "Old", @"C:\old.exe"));

        var current = new[]
        {
            Entries.Signed(AutostartVector.RunKey, "Old", @"C:\old.exe"),
            Entries.Unsigned(AutostartVector.RunKey, "AddedWhileOff", @"C:\new.exe"),
        };

        var detected = core.ReconcileFromPersistedBaseline(persisted, current, T0);

        Assert.Equal("AddedWhileOff", Assert.Single(detected).Entry.Name);
        Assert.True(core.IsSeeded);
    }

    [Fact]
    public void ReconcileFromPersistedBaseline_DropsEntriesRemovedWhileOff_FromBaseline()
    {
        var core = new PersistenceMonitorCore();
        var persisted = Ids(
            Entries.Signed(AutostartVector.RunKey, "Stay", @"C:\stay.exe"),
            Entries.Signed(AutostartVector.RunKey, "Gone", @"C:\gone.exe"));

        var current = new[] { Entries.Signed(AutostartVector.RunKey, "Stay", @"C:\stay.exe") };

        var detected = core.ReconcileFromPersistedBaseline(persisted, current, T0);

        Assert.Empty(detected);
        // Baseline is reset to exactly the current state, so the removed entry is gone.
        var baseline = core.CurrentBaseline.ToHashSet();
        Assert.Single(baseline);
        Assert.Contains(PersistenceIdentity.FromEntry(current[0]), baseline);
    }

    [Fact]
    public void ReconcileFromPersistedBaseline_IdenticalState_SurfacesNothing()
    {
        var core = new PersistenceMonitorCore();
        var same = new[] { Entries.Signed(AutostartVector.RunKey, "A", @"C:\a.exe") };

        var detected = core.ReconcileFromPersistedBaseline(Ids(same), same, T0);

        Assert.Empty(detected);
    }
}

public sealed class FilePersistenceBaselineStoreTests
{
    private static string TempPath() =>
        Path.Combine(Path.GetTempPath(), $"wsg-baseline-{Guid.NewGuid():N}.tsv");

    private static PersistenceIdentity Id(AutostartVector vector, string name, string target) =>
        PersistenceIdentity.FromEntry(Entries.Signed(vector, name, target));

    [Fact]
    public void SaveThenLoad_RoundTripsTheBaseline_AndLeavesNoTempFile()
    {
        var path = TempPath();
        try
        {
            var store = new FilePersistenceBaselineStore(path);
            var baseline = new[]
            {
                Id(AutostartVector.RunKey, "Updater", @"C:\Apps\up.exe"),
                Id(AutostartVector.Service, "Svc", @"C:\Windows\svc.exe"),
            };

            store.Save(baseline);
            var loaded = store.Load();

            Assert.NotNull(loaded);
            Assert.Equal(baseline.ToHashSet(), loaded!.ToHashSet());
            Assert.False(File.Exists(path + ".tmp"));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Load_MissingFile_ReturnsNull()
    {
        var store = new FilePersistenceBaselineStore(TempPath());
        Assert.Null(store.Load());
    }

    [Fact]
    public void Load_UnknownHeader_ReturnsNull()
    {
        var path = TempPath();
        try
        {
            File.WriteAllText(path, "garbage first line\nRunKey\tX\tc:\\x.exe\n");
            Assert.Null(new FilePersistenceBaselineStore(path).Load());
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Load_SkipsMalformedLines_KeepsValidOnes()
    {
        var path = TempPath();
        try
        {
            var store = new FilePersistenceBaselineStore(path);
            store.Save(new[] { Id(AutostartVector.RunKey, "Good", @"C:\good.exe") });
            // Append a malformed line and a line with an unknown vector.
            File.AppendAllText(path, "not\tenough\nNotAVector\tX\tc:\\x.exe\n");

            var loaded = store.Load();

            Assert.NotNull(loaded);
            Assert.Equal(Id(AutostartVector.RunKey, "Good", @"C:\good.exe"), Assert.Single(loaded!));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Save_OverwritesPreviousBaseline()
    {
        var path = TempPath();
        try
        {
            var store = new FilePersistenceBaselineStore(path);
            store.Save(new[] { Id(AutostartVector.RunKey, "First", @"C:\first.exe") });
            store.Save(new[] { Id(AutostartVector.RunKey, "Second", @"C:\second.exe") });

            var loaded = store.Load();

            Assert.Equal(Id(AutostartVector.RunKey, "Second", @"C:\second.exe"), Assert.Single(loaded!));
        }
        finally
        {
            File.Delete(path);
        }
    }
}

public sealed class PersistenceMonitorStartWithStoreTests
{
    private sealed class NoopSource : IPersistenceChangeSource
    {
#pragma warning disable CS0067 // part of the interface; this fake never raises it
        public event EventHandler<PersistenceSurfaceChangedEventArgs>? SurfaceChanged;
#pragma warning restore CS0067
        public void Start()
        {
        }

        public void Dispose()
        {
        }
    }

    private static string TempPath() =>
        Path.Combine(Path.GetTempPath(), $"wsg-baseline-{Guid.NewGuid():N}.tsv");

    [Fact]
    public void Start_WithPersistedBaseline_FiresDetectedForWhatAppearedWhileOff()
    {
        var path = TempPath();
        try
        {
            var store = new FilePersistenceBaselineStore(path);
            store.Save(new[]
            {
                PersistenceIdentity.FromEntry(Entries.Signed(AutostartVector.RunKey, "Old", @"C:\old.exe")),
            });

            var scan = new[]
            {
                Entries.Signed(AutostartVector.RunKey, "Old", @"C:\old.exe"),
                Entries.Unsigned(AutostartVector.RunKey, "AppearedWhileOff", @"C:\new.exe"),
            };

            using var monitor = new PersistenceMonitor(new NoopSource(), _ => scan, baselineStore: store);
            var detected = new List<PersistenceEvent>();
            monitor.Detected += (_, e) => detected.Add(e.Detected);

            monitor.Start();

            Assert.Equal("AppearedWhileOff", Assert.Single(detected).Entry.Name);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Start_FirstRun_IsSilent_AndPersistsBaselineForNextLaunch()
    {
        var path = TempPath();
        try
        {
            var store = new FilePersistenceBaselineStore(path);
            var scan = new[] { Entries.Unsigned(AutostartVector.RunKey, "X", @"C:\x.exe") };

            using var monitor = new PersistenceMonitor(new NoopSource(), _ => scan, baselineStore: store);
            var detected = new List<PersistenceEvent>();
            monitor.Detected += (_, e) => detected.Add(e.Detected);

            monitor.Start();

            Assert.Empty(detected);       // no persisted baseline => first run is silent
            Assert.NotNull(store.Load()); // but the baseline was written for next launch
        }
        finally
        {
            File.Delete(path);
        }
    }
}
