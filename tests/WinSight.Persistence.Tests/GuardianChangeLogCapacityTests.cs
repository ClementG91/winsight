using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// The change log is a bounded list for display. Nothing in the product acknowledges its entries, so
/// once it held 256 arrivals every later arrival in the session entered the baseline without a
/// notification. Notification must not depend on the display list having room.
/// </summary>
public sealed class GuardianChangeLogCapacityTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 14, 12, 0, 0, TimeSpan.Zero);

    private static AutostartEntry Entry(int index) =>
        Entries.Unsigned(AutostartVector.RunKey, $"Entry{index}", $@"C:\entry{index}.exe") with
        {
            Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run [Registry64]",
            Source = "Run keys",
        };

    [Fact]
    public void ArrivalsBeyondTheDisplayLogCapacityAreStillReported()
    {
        var core = new PersistenceMonitorCore();
        core.SeedBaseline([]);
        var all = Enumerable.Range(0, PersistenceChangeLog.MaxChanges + 44).Select(Entry).ToArray();

        for (var i = 0; i < PersistenceChangeLog.MaxChanges; i++)
        {
            Assert.Single(core.Reconcile(all.Take(i + 1).ToArray(), T0.AddSeconds(i)));
        }
        var late = core.Reconcile(all, T0.AddHours(1));

        Assert.Equal(44, late.Count);
        Assert.Equal(PersistenceChangeLog.MaxChanges, core.Log.Snapshot().Count);
        Assert.Equal(44, core.Log.DroppedChanges);
    }

    [Fact]
    public void AFullLogIsVisibleInMonitorDiagnostics()
    {
        var core = new PersistenceMonitorCore();
        core.SeedBaseline([]);
        core.Reconcile(Enumerable.Range(0, PersistenceChangeLog.MaxChanges + 1).Select(Entry).ToArray(), T0);

        using var monitor = new PersistenceMonitor([], new NullSource(), (_, _) =>
            new PersistenceScanResult([], PersistenceCoverage.Complete), core);

        Assert.Equal(1, monitor.Diagnostics.UnlistedArrivals);
    }

    private sealed class NullSource : IPersistenceChangeSource
    {
        public event EventHandler<PersistenceSurfaceChangedEventArgs>? SurfaceChanged
        {
            add { }
            remove { }
        }
        public void Start()
        {
        }
        public void Dispose()
        {
        }
    }
}
