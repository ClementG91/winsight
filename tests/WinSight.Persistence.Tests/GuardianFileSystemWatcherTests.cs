using WinSight.Core;
using WinSight.Persistence;

using Xunit;

namespace WinSight.Persistence.Tests;

public sealed class FileSystemWatchTargetContractTests
{
    [Fact]
    public void StartupFolderEnumerator_WatchesStartupDirectories()
    {
        var targets = new StartupFolderEnumerator().WatchTargets;

        Assert.NotEmpty(targets);
        Assert.All(targets, t => Assert.Equal(PersistenceWatchKind.FileSystem, t.Kind));
    }

    [Fact]
    public void ScheduledTaskEnumerator_WatchesTasksTreeRecursively()
    {
        var target = Assert.Single(new ScheduledTaskEnumerator().WatchTargets);

        Assert.Equal(PersistenceWatchKind.FileSystem, target.Kind);
        Assert.True(target.Recursive);
        Assert.EndsWith("Tasks", target.Path, StringComparison.OrdinalIgnoreCase);
    }
}

public sealed class FileSystemPersistenceWatcherTests
{
    [Fact]
    public void FileSystemTargets_DropsRegistryTargets_AndDeduplicates()
    {
        var targets = new[]
        {
            PersistenceWatchTarget.FileSystem(@"C:\Startup"),
            PersistenceWatchTarget.FileSystem(@"c:\startup"),
            PersistenceWatchTarget.Registry(
                Microsoft.Win32.RegistryHive.CurrentUser, Microsoft.Win32.RegistryView.Registry64, @"Software\A"),
        };

        var filtered = FileSystemPersistenceWatcher.FileSystemTargets(targets);

        Assert.Single(filtered);
        Assert.Equal(PersistenceWatchKind.FileSystem, filtered[0].Kind);
    }

    [Fact]
    public void MissingDirectory_IsSkippedNotThrown()
    {
        using var watcher = new FileSystemPersistenceWatcher(new[]
        {
            PersistenceWatchTarget.FileSystem(Path.Combine(Path.GetTempPath(), $"nope-{Guid.NewGuid():N}")),
        });
        watcher.Start();

        Assert.Equal(0, watcher.WatchedDirectoryCount);
        Assert.Equal(SensorLifecycle.Failed, watcher.SensorHealth.Lifecycle);
        Assert.True(watcher.SensorHealth.CoverageIncomplete);
    }

    [Fact]
    public void ADirectoryThatAppearsAfterStartIsRetriedAndReconciled()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"winsight-late-startup-{Guid.NewGuid():N}");
        var fired = 0;
        var watcher = new FileSystemPersistenceWatcher(
            [PersistenceWatchTarget.FileSystem(directory)],
            recoveryInterval: TimeSpan.FromHours(1));
        watcher.SurfaceChanged += (_, _) => Interlocked.Increment(ref fired);
        try
        {
            watcher.Start();
            Assert.Equal(0, watcher.ArmedLocations);

            Directory.CreateDirectory(directory);
            watcher.RetryUnavailable();

            Assert.Equal(1, watcher.ArmedLocations);
            Assert.Equal(1, Volatile.Read(ref fired)); // mandatory recovery reconciliation
            Assert.Equal(1, watcher.SensorHealth.RecoveryAttempts);
            Assert.Equal(1, watcher.SensorHealth.SuccessfulRecoveries);

            File.WriteAllText(Path.Combine(directory, "arrival.lnk"), "stub");
            Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref fired) > 1, TimeSpan.FromSeconds(30)));
            Assert.True(watcher.SensorHealth.ObservedEvents > 0);
        }
        finally
        {
            watcher.Dispose();
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void AFolderThisUserCannotWatchIsSkippedAndTheOthersStillArmAndFire()
    {
        // Unelevated, C:\Windows\System32\Tasks exists but cannot be watched: arming it threw out of
        // Start, which failed Guardian's whole start and left a standard user with no live
        // persistence monitoring at all. A deny ACE reproduces that at any privilege level.
        var denied = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"winsight-denied-{Guid.NewGuid():N}"));
        var open = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"winsight-open-{Guid.NewGuid():N}"));
        var user = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
        var deny = new System.Security.AccessControl.FileSystemAccessRule(user,
            System.Security.AccessControl.FileSystemRights.ListDirectory,
            System.Security.AccessControl.AccessControlType.Deny);
        var acl = denied.GetAccessControl();
        acl.AddAccessRule(deny);
        denied.SetAccessControl(acl);

        using var fired = new ManualResetEventSlim(false);
        using var watcher = new FileSystemPersistenceWatcher(new[]
        {
            PersistenceWatchTarget.FileSystem(denied.FullName, includeSubdirectories: true),
            PersistenceWatchTarget.FileSystem(open.FullName, includeSubdirectories: false),
        });
        watcher.SurfaceChanged += (_, _) => fired.Set();
        try
        {
            watcher.Start();

            Assert.Equal(1, watcher.WatchedDirectoryCount);
            Assert.Equal(1, watcher.ArmedLocations);
            Assert.Equal(2, watcher.RequestedLocations);
            Assert.Equal(SensorLifecycle.Running, watcher.SensorHealth.Lifecycle);
            Assert.True(watcher.SensorHealth.CoverageIncomplete);
            File.WriteAllText(Path.Combine(open.FullName, "evil.lnk"), "stub");
            Assert.True(fired.Wait(TimeSpan.FromSeconds(30)), "the watchable folder was not armed");
        }
        finally
        {
            acl.RemoveAccessRule(deny);
            denied.SetAccessControl(acl);
            denied.Delete(recursive: true);
            open.Delete(recursive: true);
        }
    }

    [Fact]
    public void CreatingAFileInAWatchedFolder_RaisesSurfaceChanged()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"winsight-startup-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);

        var fired = new ManualResetEventSlim(false);
        using var watcher = new FileSystemPersistenceWatcher(new[]
        {
            PersistenceWatchTarget.FileSystem(dir, includeSubdirectories: false),
        });
        watcher.SurfaceChanged += (_, _) => fired.Set();

        try
        {
            watcher.Start();
            Assert.Equal(1, watcher.WatchedDirectoryCount);

            File.WriteAllText(Path.Combine(dir, "evil.lnk"), "stub");

            Assert.True(fired.Wait(TimeSpan.FromSeconds(30)),
                "FileSystemWatcher did not signal within 30s of a file creation.");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}

public sealed class CompositePersistenceChangeSourceTests
{
    private sealed class FakeSource : IPersistenceChangeSource, IPersistenceWatchDiagnostics
    {
        public bool Started { get; private set; }
        public bool Disposed { get; private set; }
        public int LostObservationCount { get; set; }
        public int NotificationFailures { get; set; }
        public event EventHandler<PersistenceSurfaceChangedEventArgs>? SurfaceChanged;

        public void Raise() =>
            SurfaceChanged?.Invoke(this, new PersistenceSurfaceChangedEventArgs(Array.Empty<PersistenceWatchTarget>()));

        public void Start() => Started = true;
        public void Dispose() => Disposed = true;
    }

    [Fact]
    public void ForwardsChildSignals_AndStartsAndDisposesAllChildren()
    {
        var a = new FakeSource();
        var b = new FakeSource();
        using var composite = new CompositePersistenceChangeSource(a, b);

        var count = 0;
        composite.SurfaceChanged += (_, _) => count++;
        composite.Start();

        a.Raise();
        b.Raise();

        Assert.Equal(2, count);
        Assert.True(a.Started);
        Assert.True(b.Started);

        composite.Dispose();
        Assert.True(a.Disposed);
        Assert.True(b.Disposed);
    }

    [Fact]
    public void AggregatesSourceLossesIntoMonitorDiagnostics()
    {
        var a = new FakeSource { LostObservationCount = 2, NotificationFailures = 1 };
        var b = new FakeSource { LostObservationCount = 3, NotificationFailures = 4 };
        var composite = new CompositePersistenceChangeSource(a, b);
        using var monitor = new PersistenceMonitor([], composite,
            (_, _) => new PersistenceScanResult([], PersistenceCoverage.Complete));

        monitor.Start();

        Assert.Equal(5, composite.LostObservationCount);
        Assert.Equal(5, composite.NotificationFailures);
        Assert.Equal(5, monitor.Diagnostics.SourceLostObservations);
        Assert.Equal(5, monitor.Diagnostics.SourceNotificationFailures);
        Assert.True(monitor.Diagnostics.IsDegraded);
        Assert.False(monitor.Diagnostics.RetryableFailurePending);
    }
}
