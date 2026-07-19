using WinSight.Ransomware;

using Xunit;

namespace WinSight.Ransomware.Tests;

public sealed class RansomwareSignalClassifierTests
{
    [Theory]
    [InlineData(WatcherChangeTypes.Changed, true, RansomwareSignalKind.CanaryTouched)]
    [InlineData(WatcherChangeTypes.Deleted, true, RansomwareSignalKind.CanaryTouched)]
    [InlineData(WatcherChangeTypes.Renamed, false, RansomwareSignalKind.Rename)]
    [InlineData(WatcherChangeTypes.Deleted, false, RansomwareSignalKind.Delete)]
    public void Classify_KnownCases(WatcherChangeTypes changeType, bool isCanary, RansomwareSignalKind expected) =>
        Assert.Equal(expected, RansomwareSignalClassifier.Classify(changeType, isCanary));

    [Theory]
    [InlineData(WatcherChangeTypes.Created)]
    [InlineData(WatcherChangeTypes.Changed)]
    public void Classify_OrdinaryCreateOrChange_IsNotASignal(WatcherChangeTypes changeType) =>
        Assert.Null(RansomwareSignalClassifier.Classify(changeType, isCanary: false));
}

public sealed class CanaryManagerTests
{
    private static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"wsg-canary-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public void Plant_CreatesHiddenDecoy_RecognizedAsCanary_ThenRemoved()
    {
        var dir = TempDir();
        var manager = new CanaryManager();
        try
        {
            var canary = Assert.Single(manager.Plant(new[] { dir }));

            Assert.True(File.Exists(canary));
            Assert.True(File.GetAttributes(canary).HasFlag(FileAttributes.Hidden));
            Assert.True(manager.IsCanary(canary));
            Assert.True(manager.IsCanary(canary.ToUpperInvariant())); // case-insensitive
            Assert.False(manager.IsCanary(Path.Combine(dir, "real-user-file.txt")));

            manager.Remove();
            Assert.False(File.Exists(canary));
            Assert.False(manager.IsCanary(canary));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Plant_SkipsAMissingDirectory()
    {
        var manager = new CanaryManager();
        var planted = manager.Plant(new[] { Path.Combine(Path.GetTempPath(), $"nope-{Guid.NewGuid():N}") });
        Assert.Empty(planted);
    }

    [Fact]
    public void IsCanary_BlankPath_IsFalse() => Assert.False(new CanaryManager().IsCanary("  "));

    [Fact]
    public void RemoveOrphans_SweepsDecoysLeftByACrash_AndLeavesRealFilesAlone()
    {
        var dir = TempDir();
        try
        {
            // Simulate a previous run that died without disposing: a decoy is still on disk, and the
            // manager that planted it is gone, so only the on-disk pattern identifies it.
            var orphan = Path.Combine(dir, CanaryManager.CanaryFileName());
            File.WriteAllText(orphan, "leftover");
            File.SetAttributes(orphan, FileAttributes.Hidden);
            var userFile = Path.Combine(dir, "my-real-spreadsheet.xlsx");
            File.WriteAllText(userFile, "user data");

            var removed = CanaryManager.RemoveOrphans(new[] { dir });

            Assert.Equal(1, removed);
            Assert.False(File.Exists(orphan));
            Assert.True(File.Exists(userFile)); // a real user file is never touched
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}

public sealed class RansomwareFileWatcherTests
{
    private static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"wsg-fw-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public void TouchingACanary_RaisesDetectedImmediately()
    {
        var dir = TempDir();
        var manager = new CanaryManager();
        var canary = manager.Plant(new[] { dir })[0];

        var fired = new ManualResetEventSlim(false);
        RansomwareSignalKind? kind = null;
        using var watcher = new RansomwareFileWatcher(new[] { dir }, manager.IsCanary);
        watcher.Detected += (_, e) => { kind = e.Kind; fired.Set(); };
        try
        {
            watcher.Start();
            Assert.Equal(1, watcher.WatchedDirectoryCount);

            File.AppendAllText(canary, "encrypted-by-ransomware");

            Assert.True(fired.Wait(TimeSpan.FromSeconds(5)), "a canary touch did not fire within 5s");
            Assert.Equal(RansomwareSignalKind.CanaryTouched, kind);
        }
        finally
        {
            manager.Remove();
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void ARenameBurst_RaisesDetectedOnce()
    {
        var dir = TempDir();
        var files = new List<string>();
        for (var i = 0; i < 5; i++)
        {
            var path = Path.Combine(dir, $"doc{i}.txt");
            File.WriteAllText(path, "x");
            files.Add(path);
        }

        var fired = new ManualResetEventSlim(false);
        // Generous window so this is not timing-sensitive; threshold below the number of renames.
        var detector = new RansomwareBurstDetector(threshold: 3, window: TimeSpan.FromSeconds(30));
        using var watcher = new RansomwareFileWatcher(new[] { dir }, _ => false, detector);
        watcher.Detected += (_, _) => fired.Set();
        try
        {
            watcher.Start();
            foreach (var file in files)
            {
                File.Move(file, file + ".locked");
            }

            Assert.True(fired.Wait(TimeSpan.FromSeconds(5)), "a rename burst did not fire within 5s");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}

public sealed class RansomwareMonitorTests
{
    [Fact]
    public void Monitor_PlantsCanaries_DetectsATouch_ThenCleansUpOnDispose()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"wsg-mon-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);

        var fired = new ManualResetEventSlim(false);
        var monitor = new RansomwareMonitor(new[] { dir });
        monitor.Detected += (_, _) => fired.Set();
        try
        {
            monitor.Start();
            var canary = Assert.Single(monitor.Canaries);
            Assert.True(File.Exists(canary));

            File.AppendAllText(canary, "boom");

            Assert.True(fired.Wait(TimeSpan.FromSeconds(5)), "the monitor did not detect a canary touch");
        }
        finally
        {
            monitor.Dispose();
            Assert.Empty(Directory.GetFiles(dir)); // decoys removed on dispose
            Directory.Delete(dir, recursive: true);
        }
    }
}
