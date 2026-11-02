using System.Collections;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using WinSight.Core;
using Xunit;

namespace WinSight.Ransomware.Tests;

public sealed class CanaryOwnerProtocolTests
{
    [Fact]
    public void FutureManifestCannotBeReplacedByPlant()
    {
        using var fixture = new CanaryTestDirectory();
        var sentinel = "{\"Version\":99,\"Files\":[]}"u8.ToArray();
        File.WriteAllBytes(fixture.Manifest, sentinel);
        var manager = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        var failure = Record.Exception(() => manager.Plant([fixture.Directory]));
        // Qualifying RED observes real old publication, before the future exception contract.
        Assert.Equal(sentinel, File.ReadAllBytes(fixture.Manifest));
        Assert.IsType<IOException>(failure);
        Assert.Empty(Directory.GetFiles(fixture.Directory));
        Assert.Empty(manager.Planted);
    }

    [Fact]
    public void LegacyV2IdentityWithoutCrossSessionProofCannotAuthorizeDeletion()
    {
        using var fixture = new CanaryTestDirectory();
        var path = Path.Combine(fixture.Directory, CanaryIdentity.FileName(new byte[32], fixture.Directory, 0));
        CanaryFileIdentity identity;
        using (var lease = AutomaticFileAccess.TryCreateNewFileLease(path, CanaryDocument.For(Path.GetExtension(path))))
        {
            Assert.NotNull(lease);
            identity = CanaryFile.Identity(lease)!;
            Assert.NotNull(identity);
        }
        File.WriteAllBytes(fixture.Manifest, JsonSerializer.SerializeToUtf8Bytes(new
        {
            Version = 2,
            Files = new[] { new CanaryFileRecord(path, identity) { Owner = Guid.NewGuid().ToString("N") } },
        }));
        var before = File.ReadAllBytes(fixture.Manifest);
        Assert.Equal(0, CanaryManager.RemoveOrphans([fixture.Directory], fixture.Manifest, new byte[32]));
        Assert.True(File.Exists(path));
        Assert.Equal(before, File.ReadAllBytes(fixture.Manifest));
        var manager = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        Assert.Equal(2, manager.Plant([fixture.Directory]).Count);
        manager.Remove();
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void AnActualHeldFileGateBlocksPlantWithinItsOriginalBudget()
    {
        using var fixture = new CanaryTestDirectory();
        using var held = AutomaticFileAccess.TryAcquireExclusiveLockFile(fixture.Manifest + ".lock", out var status);
        Assert.Equal(LocalFileLockStatus.Acquired, status);
        Assert.NotNull(held);
        var manager = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest, TimeSpan.FromMilliseconds(100)));
        Assert.Throws<IOException>(() => manager.Plant([fixture.Directory]));
        Assert.Empty(Directory.GetFiles(fixture.Directory));
        Assert.Empty(manager.Planted);
    }

    [Fact]
    public void AnIncompatibleOldLocalObjectCannotControlPlant()
    {
        using var fixture = new CanaryTestDirectory();
        var key = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            Encoding.UTF8.GetBytes(Path.GetFullPath(fixture.Manifest).ToUpperInvariant())))[..32];
        using var collision = new EventWaitHandle(false, EventResetMode.ManualReset, $@"Local\WinSight.CanaryManifest.{key}");
        var manager = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        var failure = Record.Exception(() => manager.Plant([fixture.Directory]));
        Assert.Null(failure);
        Assert.Equal(3, manager.Planted.Count);
    }

    [Fact]
    public async Task DisposeCannotFinishWhileAnEnteredStartCanStillPlant()
    {
        var fixture = new CanaryTestDirectory();
        var input = fixture.TrackResource(new EnteredDirectories(fixture.Directory));
        var monitor = new RansomwareMonitor(input, null, new byte[32], fixture.Manifest);
        fixture.TrackMonitor(monitor);
        input.Arm(); // The watcher constructor may enumerate; only actual Start is witnessed.
        var entryBudget = Stopwatch.StartNew();
        // These deliberately blocking workers use dedicated threads independently of pool admission.
        var start = fixture.Track(Task.Factory.StartNew(() => Record.Exception(monitor.Start),
            CancellationToken.None, TaskCreationOptions.LongRunning | TaskCreationOptions.DenyChildAttach, TaskScheduler.Default));
        Exception? primary = null;
        try
        {
            Assert.True(WaitForEntry(input.Entered), "Start did not reach its real directory enumeration.");
            var disposeEntered = fixture.TrackResource(new ManualResetEventSlim());
            var stop = fixture.Track(Task.Factory.StartNew(() =>
            {
                disposeEntered.Set();
                monitor.Dispose();
            }, CancellationToken.None, TaskCreationOptions.LongRunning | TaskCreationOptions.DenyChildAttach, TaskScheduler.Default));
            Assert.True(WaitForEntry(disposeEntered), FormattableString.Invariant(
                $"Dispose entry was not established within the shared 4 s budget; elapsedMs={entryBudget.Elapsed.TotalMilliseconds:F1}; startStatus={start.Status}; disposeStatus={stop.Status}; signalAfterWait={disposeEntered.IsSet}."));
            // A bounded negative observation after Start has entered, not a sleep claiming entry.
            Assert.NotSame(stop, await Task.WhenAny(stop, Task.Delay(200)));
            input.Release.Set();
            await Task.WhenAll(start, stop).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Null(await start);
            Assert.Empty(monitor.Canaries);
            Assert.Empty(Directory.GetFiles(fixture.Directory));
        }
        catch (Exception ex)
        {
            primary = ex;
        }
        input.Release.Set();
        var failures = new List<Exception>();
        if (primary is not null) { failures.Add(primary); }
        // A captured old late-Start failure remains evidence even when an earlier assertion failed.
        try { await fixture.JoinWorkersAsync(); }
        catch (Exception ex) { failures.Add(ex); }
        if (start.IsCompletedSuccessfully && await start is { } startFailure) { failures.Add(startFailure); }
        try { fixture.Dispose(); }
        catch (Exception cleanup) { failures.Add(cleanup); }
        if (failures.Count == 1) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failures[0]).Throw(); }
        if (failures.Count > 1) { throw new AggregateException("Lifecycle assertion and cleanup failures.", failures); }
        bool WaitForEntry(ManualResetEventSlim signal)
        {
            // Shared four-second entry budget leaves the200ms observation inside the input's5s wait.
            var remaining = TimeSpan.FromSeconds(4) - entryBudget.Elapsed;
            return remaining > TimeSpan.Zero && signal.Wait(remaining);
        }
    }

    [Fact]
    public void AValidEmptyManifestIsDurableAccounting()
    {
        using var fixture = new CanaryTestDirectory();
        var manager = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        var paths = manager.Plant([fixture.Directory]);
        manager.Remove();
        Assert.All(paths, path => Assert.False(File.Exists(path)));
        CanaryTestDirectory.AssertEmptyManifest(fixture.Manifest);
        Assert.True(File.Exists(fixture.Manifest + ".lock"));
    }

    [Fact]
    public void OwnLifetimeDoesNotRetainAnExclusiveAncestorBootstrap()
    {
        using var fixture = new CanaryTestDirectory();
        var manager = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        Assert.Equal(3, manager.Plant([fixture.Directory]).Count);
        var sibling = Path.Combine(fixture.Root, "other-state", "state.json");
        Assert.True(AtomicFile.TryWrite(sibling, "{}"u8));
        Assert.Equal(0, CanaryManager.RemoveOrphans([fixture.Directory], fixture.Manifest, new byte[32]));
        Assert.All(manager.Planted, path => Assert.True(File.Exists(path)));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("wrong-key")]
    [InlineData("wrong-nonce")]
    [InlineData("replacement")]
    [InlineData("oversize")]
    public void UnknownOrChangedOwnerProofPreservesEveryRecord(string change)
    {
        using var fixture = new CanaryTestDirectory();
        var manager = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        var paths = manager.Plant([fixture.Directory]);
        manager.EndSessionWithoutCleanup();
        var marker = OwnerMarker(fixture.Manifest);
        var bytes = File.ReadAllBytes(marker);
        switch (change)
        {
            case "missing": File.Delete(marker); break;
            case "wrong-key": bytes[3] = bytes[3] == 'A' ? (byte)'B' : (byte)'A'; File.WriteAllBytes(marker, bytes); break;
            case "wrong-nonce": bytes[^2] = bytes[^2] == 'a' ? (byte)'b' : (byte)'a'; File.WriteAllBytes(marker, bytes); break;
            case "replacement": File.Move(marker, marker + ".original"); File.WriteAllBytes(marker, bytes); break;
            case "oversize": File.WriteAllBytes(marker, new byte[4097]); break;
        }
        var before = File.ReadAllBytes(fixture.Manifest);
        Assert.Equal(0, CanaryManager.RemoveOrphans([fixture.Directory], fixture.Manifest, new byte[32]));
        Assert.Equal(before, File.ReadAllBytes(fixture.Manifest));
        Assert.All(paths, path => Assert.True(File.Exists(path)));
    }

    [Fact]
    public void MissingDecoyIsRetiredOnlyAfterFreshDeadOwnerProofAndCountsZero()
    {
        using var fixture = new CanaryTestDirectory();
        var manager = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        var paths = manager.Plant([fixture.Directory]);
        foreach (var path in paths) { File.Delete(path); }
        Assert.Equal(0, CanaryManager.RemoveOrphans([fixture.Directory], fixture.Manifest, new byte[32]));
        Assert.Equal(3, JsonNode.Parse(File.ReadAllBytes(fixture.Manifest))!["Files"]!.AsArray().Count);
        manager.EndSessionWithoutCleanup();
        Assert.Equal(0, CanaryManager.RemoveOrphans([fixture.Directory], fixture.Manifest, new byte[32]));
        CanaryTestDirectory.AssertEmptyManifest(fixture.Manifest);
    }

    [Fact]
    public void AnAbsentPathStillReservedByAnUnknownOwnerIsNotReplanted()
    {
        using var fixture = new CanaryTestDirectory();
        var first = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        var paths = first.Plant([fixture.Directory]);
        first.EndSessionWithoutCleanup();
        File.Delete(OwnerMarker(fixture.Manifest));
        File.Delete(paths[0]);
        var next = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        Assert.Empty(next.Plant([fixture.Directory]));
        Assert.False(File.Exists(paths[0]));
        next.Remove();
        Assert.Equal(3, JsonNode.Parse(File.ReadAllBytes(fixture.Manifest))!["Files"]!.AsArray().Count);
    }

    [Fact]
    public void PlantDoesNotImplicitlySweepADeadOwner()
    {
        using var fixture = new CanaryTestDirectory();
        var first = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        var paths = first.Plant([fixture.Directory]);
        first.EndSessionWithoutCleanup();
        var next = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        Assert.Empty(next.Plant([fixture.Directory]));
        Assert.All(paths, path => Assert.True(File.Exists(path)));
        next.Remove(); // Fresh dead proof, not authority copied by Plant.
        Assert.All(paths, path => Assert.False(File.Exists(path)));
    }

    [Theory]
    [InlineData("{\"Version\":3,\"Version\":3,\"Files\":[]}")]
    [InlineData("{\"Version\":3,\"F\\u0069les\":[],\"Files\":[]}")]
    [InlineData("{\"Version\":3,\"Files\":[],\"Extra\":true}")]
    [InlineData("{\"Version\":3,\"Files\":null}")]
    [InlineData("{\"Version\":3,\"Files\":[null]}")]
    [InlineData("{\"Version\":3}")]
    [InlineData("{\"version\":3,\"Files\":[]}")]
    [InlineData("{\"Version\":\"3\",\"Files\":[]}")]
    public void InvalidWholeManifestCannotBecomeEmptyState(string json)
    {
        using var fixture = new CanaryTestDirectory();
        File.WriteAllText(fixture.Manifest, json);
        var before = File.ReadAllBytes(fixture.Manifest);
        Assert.Equal(0, CanaryManager.RemoveOrphans([fixture.Directory], fixture.Manifest, new byte[32]));
        var manager = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        Assert.Throws<IOException>(() => manager.Plant([fixture.Directory]));
        Assert.Equal(before, File.ReadAllBytes(fixture.Manifest));
        Assert.Empty(Directory.GetFiles(fixture.Directory));
    }

    [Fact]
    public void OversizedManifestRefusesPlantWithoutOwnerOrDecoyMutation()
    {
        using var fixture = new CanaryTestDirectory();
        File.WriteAllBytes(fixture.Manifest, new byte[1024 * 1024 + 1]);
        var manager = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        Assert.Throws<IOException>(() => manager.Plant([fixture.Directory]));
        Assert.Empty(Directory.GetFiles(fixture.Directory));
        Assert.Empty(Directory.GetDirectories(Path.GetDirectoryName(fixture.Manifest)!));
    }

    [Fact]
    public void AnObservedUnknownOwnerRootIsNeverRepairedOrAdopted()
    {
        using var fixture = new CanaryTestDirectory();
        var key = ManifestKey(fixture.Manifest);
        var root = Path.Combine(Path.GetDirectoryName(fixture.Manifest)!, ".canary-owners-" + key);
        Directory.CreateDirectory(root);
        var sentinel = Path.Combine(root, "operator.txt");
        File.WriteAllText(sentinel, "preserve");
        var securityBefore = new DirectoryInfo(root).GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access).GetSecurityDescriptorBinaryForm();
        var manager = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        Assert.Throws<IOException>(() => manager.Plant([fixture.Directory]));
        Assert.Equal("preserve", File.ReadAllText(sentinel));
        Assert.Equal(new[] { sentinel }, Directory.GetFiles(root));
        Assert.Equal(securityBefore, new DirectoryInfo(root).GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access).GetSecurityDescriptorBinaryForm());
        Assert.Empty(Directory.GetFiles(fixture.Directory));
    }

    [Fact]
    public void PublicationFailureRetainsProofForAZeroCountAbsentRetry()
    {
        using var fixture = new CanaryTestDirectory();
        var manager = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        var paths = manager.Plant([fixture.Directory]);
        var marker = OwnerMarker(fixture.Manifest);
        var before = File.ReadAllBytes(fixture.Manifest);
        using (var reader = new FileStream(fixture.Manifest, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            Assert.Throws<IOException>(manager.Remove);
            Assert.Equal(before, File.ReadAllBytes(fixture.Manifest));
            Assert.All(paths, path => Assert.False(File.Exists(path)));
        }
        Assert.True(File.Exists(marker));
        Assert.Equal(0, CanaryManager.RemoveOrphans([fixture.Directory], fixture.Manifest, new byte[32]));
        CanaryTestDirectory.AssertEmptyManifest(fixture.Manifest);
        Assert.False(File.Exists(marker));
    }

    [Fact]
    public void FailedAdditionalPlantDoesNotReleaseAnAlreadyActiveOwner()
    {
        using var fixture = new CanaryTestDirectory();
        var manager = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        var first = manager.Plant([fixture.Directory]).ToArray();
        var extra = Path.Combine(fixture.Root, "extra");
        Directory.CreateDirectory(extra);
        using (var reader = new FileStream(fixture.Manifest, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            Assert.Throws<IOException>(() => manager.Plant([extra]));
        }
        Assert.Equal(first, manager.Planted);
        Assert.Empty(Directory.GetFiles(extra));
        Assert.Equal(0, CanaryManager.RemoveOrphans([fixture.Directory], fixture.Manifest, new byte[32]));
        Assert.All(first, path => Assert.True(File.Exists(path)));
    }

    [Fact]
    public void FailedStartRemainsTerminalAndDisposeStillCompletes()
    {
        using var fixture = new CanaryTestDirectory();
        File.WriteAllText(fixture.Manifest, "{\"Version\":99,\"Files\":[]}");
        var monitor = new RansomwareMonitor([fixture.Directory], null, new byte[32], fixture.Manifest);
        fixture.TrackMonitor(monitor);
        Assert.Throws<IOException>(monitor.Start);
        File.Delete(fixture.Manifest);
        monitor.Start();
        monitor.Dispose();
        Assert.Empty(monitor.Canaries);
        Assert.Equal(0, monitor.WatchedDirectoryCount);
        Assert.Empty(Directory.GetFiles(fixture.Directory));
    }

    [Fact]
    public void FixedOwnerSlotsNeverEvictUnknownOccupants()
    {
        using var fixture = new CanaryTestDirectory();
        var first = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        var paths = first.Plant([fixture.Directory]);
        var marker = OwnerMarker(fixture.Manifest);
        var root = Path.GetDirectoryName(marker)!;
        for (var slot = 0; slot < 128; slot++)
        {
            var path = Path.Combine(root, $"o{slot:D3}.owner");
            if (!path.Equals(marker, StringComparison.OrdinalIgnoreCase)) { File.WriteAllText(path, "unknown-occupant"); }
        }
        var extra = Path.Combine(fixture.Root, "extra");
        Directory.CreateDirectory(extra);
        var next = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        Assert.Throws<IOException>(() => next.Plant([extra]));
        Assert.Empty(Directory.GetFiles(extra));
        for (var slot = 0; slot < 128; slot++)
        {
            var path = Path.Combine(root, $"o{slot:D3}.owner");
            if (!path.Equals(marker, StringComparison.OrdinalIgnoreCase)) { Assert.Equal("unknown-occupant", File.ReadAllText(path)); }
        }
        Assert.All(paths, path => Assert.True(File.Exists(path)));
    }

    [Fact]
    public void MoreThan1024ManifestEntriesCannotAuthorizePlant()
    {
        using var fixture = new CanaryTestDirectory();
        var identity = new CanaryFileIdentity(1, 2, 3, 4);
        var records = Enumerable.Range(0, 1025).Select(index =>
            new CanaryFileRecord(Path.Combine(fixture.Directory, $"reserved-{index}.xlsx"), identity)).ToArray();
        File.WriteAllBytes(fixture.Manifest, JsonSerializer.SerializeToUtf8Bytes(new { Version = 2, Files = records }));
        var before = File.ReadAllBytes(fixture.Manifest);
        var manager = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        Assert.Throws<IOException>(() => manager.Plant([fixture.Directory]));
        Assert.Equal(before, File.ReadAllBytes(fixture.Manifest));
        Assert.Empty(Directory.GetFiles(fixture.Directory));
    }

    [Fact]
    public void DuplicateNormalizedManifestPathsInvalidateTheWholeState()
    {
        using var fixture = new CanaryTestDirectory();
        var manager = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        var paths = manager.Plant([fixture.Directory]);
        manager.EndSessionWithoutCleanup();
        var json = JsonNode.Parse(File.ReadAllBytes(fixture.Manifest))!;
        var files = json["Files"]!.AsArray();
        var duplicate = files[0]!.DeepClone();
        duplicate["Path"] = paths[0].ToUpperInvariant();
        files.Add(duplicate);
        File.WriteAllText(fixture.Manifest, json.ToJsonString());
        var before = File.ReadAllBytes(fixture.Manifest);
        Assert.Equal(0, CanaryManager.RemoveOrphans([fixture.Directory], fixture.Manifest, new byte[32]));
        var next = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
        Assert.Throws<IOException>(() => next.Plant([fixture.Directory]));
        Assert.Equal(before, File.ReadAllBytes(fixture.Manifest));
        Assert.All(paths, path => Assert.True(File.Exists(path)));
    }

    [Fact]
    public void ForeignInheritOnlyWriteGrantRefusesOwnerRootProvisioning()
    {
        using var fixture = new CanaryTestDirectory();
        var parent = new DirectoryInfo(Path.GetDirectoryName(fixture.Manifest)!);
        var original = parent.GetAccessControl(AccessControlSections.Access).GetSecurityDescriptorBinaryForm();
        var modified = parent.GetAccessControl(AccessControlSections.Access);
        var world = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        modified.AddAccessRule(new FileSystemAccessRule(world, FileSystemRights.WriteData,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.InheritOnly, AccessControlType.Allow));
        Exception? primary = null;
        try
        {
            parent.SetAccessControl(modified);
            Assert.Contains(parent.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(),
                rule => rule.IdentityReference == world && rule.AccessControlType == AccessControlType.Allow
                    && rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly)
                    && rule.FileSystemRights.HasFlag(FileSystemRights.WriteData));
            var manager = fixture.Track(new CanaryManager(new byte[32], fixture.Manifest));
            Assert.Throws<IOException>(() => manager.Plant([fixture.Directory]));
            Assert.Empty(Directory.GetFiles(fixture.Directory));
            Assert.Empty(Directory.GetDirectories(parent.FullName));
        }
        catch (Exception ex) { primary = ex; }
        try
        {
            var restore = new DirectorySecurity();
            restore.SetSecurityDescriptorBinaryForm(original, AccessControlSections.Access);
            parent.SetAccessControl(restore);
            Assert.Equal(original, parent.GetAccessControl(AccessControlSections.Access).GetSecurityDescriptorBinaryForm());
        }
        catch (Exception cleanup)
        {
            if (primary is not null) { throw new AggregateException("ACL assertion and restoration failed.", primary, cleanup); }
            throw;
        }
        if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
    }

    private static string ManifestKey(string manifest) => Convert.ToHexString(
        System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(manifest).ToUpperInvariant())));

    private static string OwnerMarker(string manifest)
    {
        var proof = JsonNode.Parse(File.ReadAllBytes(manifest))!["Files"]![0]!["OwnerProof"];
        Assert.NotNull(proof); // Future-schema control only; never the qualifying RED oracle.
        return Path.Combine(Path.GetDirectoryName(manifest)!, ".canary-owners-" + ManifestKey(manifest),
            $"o{proof["Slot"]!.GetValue<int>():D3}.owner");
    }

    private sealed class EnteredDirectories(string directory) : IReadOnlyList<string>, IDisposable
    {
        private int _armed;
        public ManualResetEventSlim Entered { get; } = new();
        public ManualResetEventSlim Release { get; } = new();
        public int Count => 1;
        public string this[int index] => index == 0 ? directory : throw new ArgumentOutOfRangeException(nameof(index));
        public void Arm() => Volatile.Write(ref _armed, 1);
        public IEnumerator<string> GetEnumerator()
        {
            if (Interlocked.Exchange(ref _armed, 0) == 1)
            {
                Entered.Set();
                if (!Release.Wait(TimeSpan.FromSeconds(5))) { throw new TimeoutException("Start enumeration was not released."); }
            }
            yield return directory;
        }
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        public void Dispose() { Entered.Dispose(); Release.Dispose(); }
    }
}

/// <summary>Only test-owned roots are protected or recursively removed; no operator/TEMP ACL changes.</summary>
internal sealed class CanaryTestDirectory : IDisposable
{
    private static readonly ConcurrentDictionary<string, CanaryTestDirectory> Families = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<CanaryManager> _managers = [];
    private readonly List<RansomwareMonitor> _monitors = [];
    private readonly List<Task> _workers = [];
    private readonly List<IDisposable> _resources = [];
    private bool _disposed;
    public string Root { get; }
    public string Directory { get; }
    public string Manifest { get; }

    public CanaryTestDirectory()
    {
        Root = System.IO.Directory.CreateTempSubdirectory("winsight-canary-private-").FullName;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var user = identity.User ?? throw new InvalidOperationException("No token SID.");
            var actualOwner = new DirectoryInfo(Root).GetAccessControl(AccessControlSections.Owner)
                .GetOwner(typeof(SecurityIdentifier));
            Assert.Contains(actualOwner, new[] { user,
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) });
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            foreach (var sid in new[] { user, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) }.Distinct())
            {
                security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            }
            new DirectoryInfo(Root).SetAccessControl(security);
            var applied = new DirectoryInfo(Root).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
            Assert.True(applied.AreAccessRulesProtected);
            Assert.Equal(actualOwner, applied.GetOwner(typeof(SecurityIdentifier)));
            Assert.All(applied.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(), rule =>
            {
                Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
                Assert.Contains(rule.IdentityReference, new[] { user,
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) });
                Assert.Equal(FileSystemRights.FullControl, rule.FileSystemRights);
            });
            Directory = Path.Combine(Root, "decoys");
            System.IO.Directory.CreateDirectory(Directory);
            var state = Path.Combine(Root, "state");
            System.IO.Directory.CreateDirectory(state);
            Manifest = Path.Combine(state, "manifest.json");
            Families[Manifest] = this;
            Families[Directory] = this;
        }
        catch (Exception primary)
        {
            try { System.IO.Directory.Delete(Root, true); }
            catch (Exception cleanup) { throw new AggregateException("Private fixture setup and cleanup failed.", primary, cleanup); }
            throw;
        }
    }

    public T TrackResource<T>(T resource) where T : IDisposable { _resources.Add(resource); return resource; }
    public CanaryManager Track(CanaryManager manager) { _managers.Add(manager); return manager; }
    public T Track<T>(T task) where T : Task { _workers.Add(task); return task; }
    public void TrackMonitor(RansomwareMonitor monitor) => _monitors.Add(monitor);
    public static CanaryManager TrackForManifest(CanaryManager manager, string manifest) => Families[manifest].Track(manager);
    public static string CreateManifestPath() => new CanaryTestDirectory().Manifest;
    public static string CreateDecoyDirectory() => new CanaryTestDirectory().Directory;
    public static string ManifestForDirectory(string directory) => Families[directory].Manifest;
    public static void DeleteManifestFamily(string manifest) => Families[manifest].Dispose();
    public static void DeleteDirectoryFamily(string directory) => Families[directory].Dispose();
    public static void AssertEmptyManifest(string manifest)
    {
        using var json = JsonDocument.Parse(File.ReadAllBytes(manifest));
        Assert.Equal(3, json.RootElement.GetProperty("Version").GetInt32());
        Assert.Equal(0, json.RootElement.GetProperty("Files").GetArrayLength());
    }
    public async Task JoinWorkersAsync() => await Task.WhenAll(_workers).WaitAsync(TimeSpan.FromSeconds(5));
    public void WaitForWorkers()
    {
        if (_workers.Count > 0 && !Task.WhenAll(_workers).Wait(TimeSpan.FromSeconds(5)))
        {
            throw new TimeoutException("Retained canary test workers did not stop; preserve root and witnesses.");
        }
    }
    public void Dispose()
    {
        if (_disposed) { return; }
        var errors = new List<Exception>();
        try { WaitForWorkers(); }
        catch (Exception ex) { errors.Add(ex); }
        if (_workers.Any(task => !task.IsCompleted)) { throw new AggregateException("Active test worker; root preserved.", errors); }
        foreach (var monitor in _monitors)
        {
            // Cleanup-only reflection closes the old implementation's late-Plant leak after workers joined.
            var field = typeof(RansomwareMonitor).GetField("_canaries", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
            try { monitor.Dispose(); }
            catch (Exception ex) { errors.Add(ex); }
            finally
            {
                try { (field?.GetValue(monitor) as CanaryManager)?.EndSessionWithoutCleanup(); }
                catch (Exception ex) { errors.Add(ex); }
            }
        }
        foreach (var manager in _managers) { manager.EndSessionWithoutCleanup(); }
        foreach (var resource in _resources) { resource.Dispose(); }
        try { System.IO.Directory.Delete(Root, true); }
        catch (Exception ex) { errors.Add(ex); }
        _disposed = true;
        Families.TryRemove(Manifest, out _);
        Families.TryRemove(Directory, out _);
        if (errors.Count > 0) { throw new AggregateException("Canary fixture cleanup failed.", errors); }
    }
}
