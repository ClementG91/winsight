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

    private static CanaryManager Manager(out string manifest)
    {
        manifest = Path.Combine(Path.GetTempPath(), $"wsg-manifest-{Guid.NewGuid():N}.txt");
        // A fixed seed keeps the assertions deterministic; production derives one per machine.
        return new CanaryManager(seed: new byte[32], manifestPath: manifest);
    }

    /// <summary>
    /// Decoys are ordinary, visible files, several per directory - the inverse of what this test
    /// asserted before.
    /// </summary>
    /// <remarks>
    /// <b>Hidden was wrong.</b> A decoy exists to be found by the enumeration ransomware performs,
    /// and a good many families skip hidden files deliberately, so the attribute removed the decoy
    /// from precisely the sweep it was planted for.
    ///
    /// <b>One per directory was wrong.</b> A single decoy is reached at whatever point of the walk
    /// its name falls, so a lone decoy sorting late is touched only after the documents it was
    /// protecting have already been encrypted.
    /// </remarks>
    [Fact]
    public void Plant_CreatesSeveralVisibleDecoys_RecognizedAsCanaries_ThenRemoved()
    {
        var dir = TempDir();
        var manager = Manager(out var manifest);
        try
        {
            var canaries = manager.Plant(new[] { dir });

            Assert.Equal(CanaryIdentity.PerDirectory, canaries.Count);
            Assert.Equal(canaries.Count, canaries.Distinct(StringComparer.OrdinalIgnoreCase).Count());
            foreach (var canary in canaries)
            {
                Assert.True(File.Exists(canary));
                Assert.False(File.GetAttributes(canary).HasFlag(FileAttributes.Hidden));
                Assert.True(manager.IsCanary(canary));
                Assert.True(manager.IsCanary(canary.ToUpperInvariant())); // case-insensitive
            }
            Assert.False(manager.IsCanary(Path.Combine(dir, "real-user-file.txt")));

            manager.Remove();
            foreach (var canary in canaries)
            {
                Assert.False(File.Exists(canary));
                Assert.False(manager.IsCanary(canary));
            }
        }
        finally
        {
            File.Delete(manifest);
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>
    /// A decoy that announces itself is not a decoy. Evading the whole feature used to be one line
    /// against a constant published in this repository.
    /// </summary>
    [Fact]
    public void ADecoyNameCarriesNoRecognisableMarker()
    {
        var dir = TempDir();
        var manager = Manager(out var manifest);
        try
        {
            foreach (var canary in manager.Plant(new[] { dir }))
            {
                var name = Path.GetFileName(canary);
                Assert.DoesNotContain("winsight", name, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("canary", name, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("decoy", name, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("guard", name, StringComparison.OrdinalIgnoreCase);
            }
        }
        finally
        {
            manager.Remove();
            File.Delete(manifest);
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>
    /// Two machines must not plant the same names, or the seed buys nothing over the old constant.
    /// </summary>
    [Fact]
    public void TwoSeedsProduceDifferentNames()
    {
        var first = CanaryIdentity.FileName(new byte[32], @"C:\Users\x\Documents", 0);
        var second = CanaryIdentity.FileName(
            System.Security.Cryptography.RandomNumberGenerator.GetBytes(32),
            @"C:\Users\x\Documents",
            0);

        Assert.NotEqual(first, second);
    }

    /// <summary>The same seed must reproduce the same name, or a later run cannot recognise its own.</summary>
    [Fact]
    public void TheSameSeedIsDeterministic()
    {
        var seed = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);

        Assert.Equal(
            CanaryIdentity.FileName(seed, @"C:\Users\x\Documents", 1),
            CanaryIdentity.FileName(seed, @"C:\Users\x\Documents", 1));
    }

    /// <summary>
    /// Decoys must not all sit at one end of an alphabetical directory walk, or the late ones are
    /// reached only after the encryption they exist to interrupt.
    /// </summary>
    [Fact]
    public void DecoysSpanTheAlphabeticalWalk()
    {
        var seed = new byte[32];
        var names = Enumerable.Range(0, CanaryIdentity.PerDirectory)
            .Select(index => CanaryIdentity.FileName(seed, @"C:\Users\x\Documents", index))
            .ToList();

        Assert.Equal(names.Count, names.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Contains(names, name => char.IsAsciiDigit(name[0]));
        Assert.Contains(names, name => char.ToLowerInvariant(name[0]) > 'r');
    }

    /// <summary>
    /// The decoy must be the format its extension claims: a .xlsx that is plain text is identifiable
    /// from its first four bytes, and several families check a magic number before encrypting.
    /// </summary>
    [Fact]
    public void ADecoyIsARealOoxmlPackage()
    {
        var dir = TempDir();
        var manager = Manager(out var manifest);
        try
        {
            var canary = manager.Plant(new[] { dir })
                .First(path => path.EndsWith(".xlsx", StringComparison.OrdinalIgnoreCase));

            var header = new byte[4];
            using (var stream = File.OpenRead(canary))
            {
                Assert.Equal(4, stream.Read(header, 0, 4));
            }
            Assert.Equal([0x50, 0x4B, 0x03, 0x04], header); // "PK\x03\x04"

            using var archive = System.IO.Compression.ZipFile.OpenRead(canary);
            Assert.Contains(archive.Entries, entry => entry.FullName == "[Content_Types].xml");
            Assert.Contains(archive.Entries, entry => entry.FullName == "xl/workbook.xml");

            // And nothing inside it names the product.
            var bytes = File.ReadAllBytes(canary);
            Assert.DoesNotContain(
                "WinSight",
                System.Text.Encoding.ASCII.GetString(bytes),
                StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            manager.Remove();
            File.Delete(manifest);
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>A real file that happens to collide is never overwritten.</summary>
    [Fact]
    public void AnExistingFileIsNeverOverwritten()
    {
        var dir = TempDir();
        var manager = Manager(out var manifest);
        try
        {
            var collision = Path.Combine(dir, CanaryIdentity.FileName(new byte[32], dir, 0));
            File.WriteAllText(collision, "the user's actual document");

            manager.Plant(new[] { dir });

            Assert.Equal("the user's actual document", File.ReadAllText(collision));
            Assert.False(manager.IsCanary(collision));
        }
        finally
        {
            manager.Remove();
            File.Delete(manifest);
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Plant_SkipsAMissingDirectory()
    {
        var manager = Manager(out var manifest);
        try
        {
            var planted = manager.Plant(new[] { Path.Combine(Path.GetTempPath(), $"nope-{Guid.NewGuid():N}") });
            Assert.Empty(planted);
        }
        finally
        {
            File.Delete(manifest);
        }
    }

    [Fact]
    public void IsCanary_BlankPath_IsFalse()
    {
        var manager = Manager(out var manifest);
        try
        {
            Assert.False(manager.IsCanary("  "));
        }
        finally
        {
            File.Delete(manifest);
        }
    }

    /// <summary>
    /// Orphan recovery moved from a name pattern to a manifest, because the names deliberately carry
    /// no pattern any more.
    /// </summary>
    [Fact]
    public void RemoveOrphans_SweepsDecoysRecordedByACrashedRun_AndLeavesRealFilesAlone()
    {
        var dir = TempDir();
        var manager = Manager(out var manifest);
        try
        {
            var planted = manager.Plant(new[] { dir });
            var userFile = Path.Combine(dir, "my-real-spreadsheet.xlsx");
            File.WriteAllText(userFile, "user data");

            // Simulate a run that died without disposing: the decoys are still on disk and the
            // manager that planted them is gone, so only the manifest identifies them.
            var removed = CanaryManager.RemoveOrphans(new[] { dir }, manifest, new byte[32]);

            Assert.Equal(planted.Count, removed);
            Assert.All(planted, path => Assert.False(File.Exists(path)));
            Assert.True(File.Exists(userFile)); // a real user file is never touched
            Assert.False(File.Exists(manifest));
        }
        finally
        {
            File.Delete(manifest);
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void RemoveOrphans_RejectsManifestPathsThatWereNotExpectedCanaries()
    {
        var dir = TempDir();
        var outside = Path.Combine(Path.GetTempPath(), $"wsg-real-{Guid.NewGuid():N}.txt");
        var manifest = Path.Combine(Path.GetTempPath(), $"wsg-manifest-{Guid.NewGuid():N}.txt");
        try
        {
            var inside = Path.Combine(dir, "my-real-spreadsheet.xlsx");
            File.WriteAllText(inside, "user data");
            File.WriteAllText(outside, "user data");
            File.WriteAllLines(manifest, new[] { inside, outside, @"..\relative.txt" });

            var removed = CanaryManager.RemoveOrphans(
                new[] { dir }, manifest, new byte[32]);

            Assert.Equal(0, removed);
            Assert.True(File.Exists(inside));
            Assert.True(File.Exists(outside));
            Assert.False(File.Exists(manifest));
        }
        finally
        {
            File.Delete(manifest);
            File.Delete(outside);
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>
    /// Decoys planted by a version that used the published prefix must still be cleaned up, or an
    /// upgrade strands hidden files in the operator's folders forever.
    /// </summary>
    [Fact]
    public void RemoveOrphans_StillSweepsTheLegacyNamingScheme()
    {
        var dir = TempDir();
        var manifest = Path.Combine(Path.GetTempPath(), $"wsg-manifest-{Guid.NewGuid():N}.txt");
        try
        {
            var legacy = Path.Combine(dir, $"WinSightGuard_{Guid.NewGuid():N}.xlsx");
            File.WriteAllText(legacy, CanaryIdentity.LegacyContent);
            File.SetAttributes(legacy, FileAttributes.Hidden);
            var lookalike = Path.Combine(dir, $"WinSightGuard_{Guid.NewGuid():N}.xlsx");
            File.WriteAllText(lookalike, "real user data");
            var userFile = Path.Combine(dir, "my-real-spreadsheet.xlsx");
            File.WriteAllText(userFile, "user data");

            var removed = CanaryManager.RemoveOrphans(new[] { dir }, manifest);

            Assert.Equal(1, removed);
            Assert.False(File.Exists(legacy));
            Assert.True(File.Exists(lookalike));
            Assert.True(File.Exists(userFile));
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
        var manager = new CanaryManager(
            seed: new byte[32],
            manifestPath: Path.Combine(Path.GetTempPath(), $"wsg-manifest-{Guid.NewGuid():N}.txt"));
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
    /// <summary>
    /// A directory that was never watched is counted, not dropped.
    /// </summary>
    /// <remarks>
    /// It was silently skipped. A caller comparing what it asked for against what is watched could
    /// have inferred the difference; nothing did, and the difference is exactly the set of folders
    /// nobody is observing - on the detector whose entire promise is that "I could not see" is never
    /// reported as "nothing there".
    /// </remarks>
    [Fact]
    public void ADirectoryThatCannotBeWatchedIsCountedRatherThanDropped()
    {
        var absent = Path.Combine(Path.GetTempPath(), $"winsight-absent-{Guid.NewGuid():N}");
        using var watcher = new RansomwareFileWatcher([absent], _ => false);

        watcher.Start();

        Assert.Equal(0, watcher.WatchedDirectoryCount);
        Assert.Equal(1, watcher.UnwatchableDirectoryCount);
        Assert.True(watcher.CoverageIsIncomplete);
    }

    /// <summary>
    /// A watch that overflows and cannot be re-armed stops counting as live.
    /// </summary>
    /// <remarks>
    /// The re-arm in the error handler is best-effort, and when it fails the watcher stayed in the
    /// list, dead, still counted. The dashboard reported the directory as watched while it had been
    /// blind since the first burst - the same silent false negative this class was rebuilt to
    /// remove, one level up.
    /// </remarks>
    [Fact]
    public void AWatchOnADeletedDirectoryStopsCountingAsLive()
    {
        var directory = TempDir();
        var watcher = new RansomwareFileWatcher([directory], _ => false);
        try
        {
            watcher.Start();
            Assert.Equal(1, watcher.WatchedDirectoryCount);

            Directory.Delete(directory, recursive: true);

            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (watcher.WatchedDirectoryCount != 0 && DateTime.UtcNow < deadline)
            {
                Thread.Sleep(50);
            }

            Assert.Equal(0, watcher.WatchedDirectoryCount);
            Assert.Equal(1, watcher.LostWatchCount);
            Assert.True(watcher.CoverageIsIncomplete);
        }
        finally
        {
            watcher.Dispose();
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
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
            // Several decoys per directory now, spanning an alphabetical walk. Touching any one of
            // them is the signal, so the test uses the first.
            Assert.Equal(CanaryIdentity.PerDirectory, monitor.Canaries.Count);
            var canary = monitor.Canaries[0];
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

    [Fact]
    public void Monitor_ReArmsAfterAnAlert_SoASecondWaveStillFires()
    {
        // A security tool that alerts once per session and then goes quiet is worse than one that
        // never alerted: the operator would trust a silence that no longer means "nothing happened".
        var dir = Path.Combine(Path.GetTempPath(), $"wsg-mon-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);

        var detections = new System.Collections.Concurrent.ConcurrentQueue<RansomwareDetectedEventArgs>();
        var first = new ManualResetEventSlim(false);
        var second = new ManualResetEventSlim(false);
        // No cooldown, because this test is about re-arming: the two waves are milliseconds apart
        // and the default thirty-second quiet period would suppress the second one, which is the
        // cooldown working rather than the latch failing. The cooldown has its own tests.
        var monitor = new RansomwareMonitor(
            new[] { dir }, new RansomwareBurstDetector(cooldown: TimeSpan.Zero));
        monitor.Detected += (_, e) =>
        {
            detections.Enqueue(e);
            if (detections.Count == 1)
            {
                first.Set();
            }
            else if (detections.Count == 2)
            {
                second.Set();
            }
        };
        try
        {
            monitor.Start();
            var canary = monitor.Canaries[0];

            File.AppendAllText(canary, "first-touch");
            Assert.True(first.Wait(TimeSpan.FromSeconds(5)), "the first canary touch never alerted");

            // The decoy is gone after a real touch is fine to keep touching for this test; what
            // matters is that the detector — not the canary — is ready to fire again immediately.
            File.AppendAllText(canary, "second-touch");
            Assert.True(second.Wait(TimeSpan.FromSeconds(5)),
                "a second touch after the first alert produced no second alert — the detector did not re-arm");
        }
        finally
        {
            monitor.Dispose();
            Directory.Delete(dir, recursive: true);
        }
    }
}
