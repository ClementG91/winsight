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

            Assert.True(fired.Wait(TimeSpan.FromSeconds(5)),
                "FileSystemWatcher did not signal within 5s of a file creation.");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}

public sealed class CompositePersistenceChangeSourceTests
{
    private sealed class FakeSource : IPersistenceChangeSource
    {
        public bool Started { get; private set; }
        public bool Disposed { get; private set; }
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
}
