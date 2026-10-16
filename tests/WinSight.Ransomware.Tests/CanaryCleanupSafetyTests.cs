using System.Text.Json;
using WinSight.Core;
using Xunit;

namespace WinSight.Ransomware.Tests;

public sealed class CanaryCleanupSafetyTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void CleanupPreservesAReplacementEvenWhenItsBytesAreIdentical(bool crossRun, bool identicalBytes)
    {
        WithCanaries((manager, paths, directory, manifest) =>
        {
            var path = paths[0];
            var content = identicalBytes ? File.ReadAllBytes(path) : "actual user document"u8.ToArray();
            // Keep the original file alive under another name to prove this is a distinct identity.
            File.Move(path, Path.Combine(directory, "moved-original.xlsx"));
            File.WriteAllBytes(path, content);
            Cleanup(manager, directory, manifest, crossRun);
            Assert.Equal(content, File.ReadAllBytes(path));
            Assert.All(paths.Skip(1), other => Assert.False(File.Exists(other)));
        });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CleanupPreservesAnOriginalThatNowContainsUserEdits(bool crossRun)
    {
        WithCanaries((manager, paths, directory, manifest) =>
        {
            var path = paths[0];
            // Same file identity and same length: content comparison must still reject it.
            using (var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
            {
                writer.Write("USER"u8);
            }
            var edited = File.ReadAllBytes(path);
            Cleanup(manager, directory, manifest, crossRun);
            Assert.Equal(edited, File.ReadAllBytes(path));
            Assert.All(paths.Skip(1), other => Assert.False(File.Exists(other)));
        });
    }

    [Fact]
    public void CleanupPreservesFilesWithAnOpenWriter()
    {
        WithCanaries((manager, paths, _, _) =>
        {
            using var writer = new FileStream(paths[0], FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            manager.Remove();
            Assert.True(File.Exists(paths[0]));
        });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LockedOriginalCanBeRetriedAfterItsWriterCloses(bool crossRun)
    {
        WithCanaries((manager, paths, directory, manifest) =>
        {
            using (var writer = new FileStream(paths[0], FileMode.Open, FileAccess.Write,
                       FileShare.ReadWrite | FileShare.Delete))
            {
                Cleanup(manager, directory, manifest, crossRun);
                Assert.True(File.Exists(paths[0]));
                Assert.True(File.Exists(manifest));
            }
            if (crossRun)
            {
                Assert.Equal(1, CanaryManager.RemoveOrphans([directory], manifest, new byte[32]));
            }
            else
            {
                manager.Remove();
            }
            Assert.False(File.Exists(paths[0]));
            CanaryTestDirectory.AssertEmptyManifest(manifest);
        });
    }

    [Fact]
    public void NewSessionPlantingDoesNotLoseALockedOriginalFromThePriorManifest()
    {
        WithCanaries((manager, paths, directory, manifest) =>
        {
            var nextRun = CanaryTestDirectory.TrackForManifest(new CanaryManager(new byte[32], manifest), manifest);
            using (var writer = new FileStream(paths[0], FileMode.Open, FileAccess.Write,
                       FileShare.ReadWrite | FileShare.Delete))
            {
                manager.Remove();
                Assert.Equal(0, CanaryManager.RemoveOrphans([directory], manifest, new byte[32]));
                Assert.Equal(2, nextRun.Plant([directory]).Count);
            }
            nextRun.Remove();
            Assert.All(paths, path => Assert.False(File.Exists(path)));
            CanaryTestDirectory.AssertEmptyManifest(manifest);
        });
    }

    [Fact]
    public void LegacyPathOnlyManifestCannotDeleteEvenAPristineExpectedFile()
    {
        WithCanaries((_, paths, directory, manifest) =>
        {
            File.WriteAllLines(manifest, paths);
            Assert.Equal(0, CanaryManager.RemoveOrphans([directory], manifest, new byte[32]));
            Assert.All(paths, path => Assert.True(File.Exists(path)));
        });
    }

    [Theory]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("{\"Version\":2,\"Files\":[null]}")]
    [InlineData("{\"Version\":2,\"Files\":null}")]
    [InlineData("{\"Version\":99,\"Files\":[]}")]
    public void MalformedOrUnknownManifestDoesNotDeleteDecoys(string content)
    {
        WithCanaries((_, paths, directory, manifest) =>
        {
            File.WriteAllText(manifest, content);
            Assert.Equal(0, CanaryManager.RemoveOrphans([directory], manifest, new byte[32]));
            Assert.All(paths, path => Assert.True(File.Exists(path)));
        });
    }

    [Fact]
    public void OversizedManifestDoesNotTriggerUnboundedCleanup()
    {
        WithCanaries((_, paths, directory, manifest) =>
        {
            File.WriteAllText(manifest, new string(' ', 1024 * 1024 + 1));
            Assert.Equal(0, CanaryManager.RemoveOrphans([directory], manifest, new byte[32]));
            Assert.All(paths, path => Assert.True(File.Exists(path)));
        });
    }

    [Fact]
    public void RecordedIdentityCannotAuthoriseADifferentPath()
    {
        WithCanaries((manager, paths, directory, manifest) =>
        {
            var bytes = File.ReadAllBytes(paths[0]);
            var saved = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllBytes(manifest))!;
            var original = saved["Files"]!.AsArray().Single(record => record!["Path"]!.GetValue<string>() == paths[0])!.DeepClone();
            manager.EndSessionWithoutCleanup();
            var outside = Path.Combine(directory, "real-user-file.xlsx");
            File.Move(paths[0], outside);
            original["Path"] = outside; // Only the path changes; exact identity and dead-owner proof remain valid.
            saved["Files"] = new System.Text.Json.Nodes.JsonArray(original);
            File.WriteAllText(manifest, saved.ToJsonString());
            Assert.Equal(0, CanaryManager.RemoveOrphans([directory], manifest, new byte[32]));
            Assert.Equal(bytes, File.ReadAllBytes(outside));
        });
    }

    [Fact]
    public void RecordsForADirectoryOutsideThisSessionAreKeptUntilThatDirectoryIsCleaned()
    {
        using var fixture = new CanaryTestDirectory();
        var root = fixture.Root;
        var documents = Path.Combine(root, "Documents");
        var downloads = Path.Combine(root, "Downloads");
        Directory.CreateDirectory(documents);
        Directory.CreateDirectory(downloads);
        var manifest = fixture.Manifest;
        try
        {
            // A session that protected both folders ended without cleanup (crash, reboot).
            var crashed = fixture.Track(new CanaryManager(new byte[32], manifest));
            var plantedByCrashed = crashed.Plant([documents, downloads]);
            crashed.EndSessionWithoutCleanup();
            var leftBehind = plantedByCrashed
                .Where(path => path.StartsWith(downloads, StringComparison.OrdinalIgnoreCase)).ToList();
            Assert.Equal(3, leftBehind.Count);

            // The next sessions manage Documents only (Downloads was unavailable at that moment).
            Assert.Equal(3, CanaryManager.RemoveOrphans([documents], manifest, new byte[32]));
            var next = fixture.Track(new CanaryManager(new byte[32], manifest));
            next.Plant([documents]);
            next.Remove();

            Assert.All(leftBehind, path => Assert.True(File.Exists(path)));
            Assert.Equal(3, CanaryManager.RemoveOrphans([downloads], manifest, new byte[32]));
            Assert.All(leftBehind, path => Assert.False(File.Exists(path)));
            CanaryTestDirectory.AssertEmptyManifest(manifest);
        }
        finally
        {
            fixture.WaitForWorkers();
        }
    }

    [Fact]
    public async Task AConcurrentOrphanSweepNeverDiscardsTheRecordsOfDecoysPlantedMeanwhile()
    {
        // The dashboard sweeps orphans on a background task at launch while restored protection runs
        // RemoveOrphans + Plant on the same manifest; two dashboards can also run at once. A sweep
        // that read the manifest before the plant and wrote after it erased the new decoys' records,
        // stranding them after the next crash.
        using var fixture = new CanaryTestDirectory();
        var root = fixture.Root;
        var previous = Path.Combine(root, "previous");
        var current = Path.Combine(root, "current");
        Directory.CreateDirectory(previous);
        Directory.CreateDirectory(current);
        var manifest = fixture.Manifest;
        var seed = new byte[32];
        try
        {
            for (var iteration = 0; iteration < 60; iteration++)
            {
                // A crashed session left decoys in "previous".
                var crashed = fixture.Track(new CanaryManager(seed, manifest));
                crashed.Plant([previous]);
                crashed.EndSessionWithoutCleanup();

                var session = fixture.Track(new CanaryManager(seed, manifest));
                var go = fixture.TrackResource(new ManualResetEventSlim());
                var sweep = fixture.Track(Task.Run(() =>
                {
                    if (!go.Wait(TimeSpan.FromSeconds(5))) { throw new TimeoutException("Race start was not released."); }
                    CanaryManager.RemoveOrphans([previous, current], manifest, seed);
                }));
                var start = fixture.Track(Task.Run(() =>
                {
                    if (!go.Wait(TimeSpan.FromSeconds(5))) { throw new TimeoutException("Race start was not released."); }
                    CanaryManager.RemoveOrphans([current], manifest, seed);
                    session.Plant([current]);
                }));
                go.Set();
                await Task.WhenAll(sweep, start).WaitAsync(TimeSpan.FromSeconds(5));
                // Whatever the order, the live session's decoys were not swept out from under it.
                Assert.Equal(3, session.Planted.Count);
                Assert.All(session.Planted, path => Assert.True(File.Exists(path)));

                session.EndSessionWithoutCleanup();
                // Simulated crash of the new session: the next launch must still find its decoys.
                CanaryManager.RemoveOrphans([previous, current], manifest, seed);
                Assert.Empty(Directory.GetFiles(current));
                Assert.Empty(Directory.GetFiles(previous));
            }
        }
        finally
        {
            fixture.WaitForWorkers();
        }
    }

    [Fact]
    public void AnotherSessionsLiveDecoysAreNotOrphansUntilThatSessionEnds()
    {
        WithCanaries((manager, paths, directory, manifest) =>
        {
            // A second dashboard sweeping at launch: deleting these would blind the running session
            // and raise its "decoy deleted" alert.
            Assert.Equal(0, CanaryManager.RemoveOrphans([directory], manifest, new byte[32]));
            Assert.All(paths, path => Assert.True(File.Exists(path)));

            // Nor does a new session adopt them for its own cleanup.
            var other = CanaryTestDirectory.TrackForManifest(new CanaryManager(new byte[32], manifest), manifest);
            other.Plant([directory]);
            other.Remove();
            Assert.All(paths, path => Assert.True(File.Exists(path)));

            manager.EndSessionWithoutCleanup();
            Assert.Equal(3, CanaryManager.RemoveOrphans([directory], manifest, new byte[32]));
        });
    }

    [Fact]
    public void AnInterruptedManifestWriteLeavesThePreviousManifestReadable()
    {
        WithCanaries((manager, paths, directory, manifest) =>
        {
            var before = File.ReadAllBytes(manifest);
            // A crash during the replacement leaves only a temporary file beside the manifest.
            File.WriteAllBytes($"{manifest}.{Guid.NewGuid():N}.tmp", before.AsSpan(0, before.Length / 2).ToArray());

            manager.EndSessionWithoutCleanup();
            Assert.Equal(3, CanaryManager.RemoveOrphans([directory], manifest, new byte[32]));
        });
    }

    [Fact]
    public void DisposingAMonitorThatNeverPlantedLeavesEveryoneElsesRecordsAlone()
    {
        WithCanaries((manager, paths, directory, manifest) =>
        {
            manager.EndSessionWithoutCleanup(); // a crashed run's records, awaiting cleanup
            var before = File.ReadAllBytes(manifest);
            var lastWrite = File.GetLastWriteTimeUtc(manifest);

            // Protection toggled on then off before planting, or a default host disposed unstarted.
            new CanaryManager(new byte[32], manifest).Remove();

            Assert.Equal(before, File.ReadAllBytes(manifest));
            Assert.Equal(lastWrite, File.GetLastWriteTimeUtc(manifest));
            Assert.Equal(3, CanaryManager.RemoveOrphans([directory], manifest, new byte[32]));
        });
    }

    [Fact]
    public void ManifestLockTimeoutPlantsNothingAndDoesNotClaimSessionOwnership()
    {
        using var fixture = new CanaryTestDirectory();
        var directory = fixture.Directory;
        var manifest = fixture.Manifest;
        using var held = AutomaticFileAccess.TryAcquireExclusiveLockFile(manifest + ".lock", out var status);
        Assert.Equal(LocalFileLockStatus.Acquired, status);
        Assert.NotNull(held);
        var manager = fixture.Track(new CanaryManager(new byte[32], manifest, TimeSpan.FromMilliseconds(100)));
        Assert.Throws<IOException>(() => manager.Plant([directory]));
        Assert.Empty(System.IO.Directory.GetFiles(directory));
    }

    private static void Cleanup(CanaryManager manager, string directory, string manifest, bool crossRun)
    {
        if (crossRun)
        {
            manager.EndSessionWithoutCleanup(); // the planting run crashed
            Assert.Equal(2, CanaryManager.RemoveOrphans([directory], manifest, new byte[32]));
        }
        else
        {
            manager.Remove();
        }
    }

    private static void WithCanaries(Action<CanaryManager, IReadOnlyList<string>, string, string> action)
    {
        using var fixture = new CanaryTestDirectory();
        var directory = fixture.Directory;
        var manifest = fixture.Manifest;
        var manager = fixture.Track(new CanaryManager(new byte[32], manifest));
        var paths = manager.Plant([directory]);
        Assert.Equal(3, paths.Count);
        action(manager, paths, directory, manifest);
        // Intentionally corrupt manifest tests must not invoke new cleanup authority in teardown.
        // The fixture releases every tracked owner and strictly deletes only its own private root.
    }
}
