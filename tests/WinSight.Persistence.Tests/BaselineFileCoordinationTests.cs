using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;

using WinSight.Core;

using Xunit;

namespace WinSight.Persistence.Tests;

public sealed class BaselineFileCoordinationTests
{
    private static PersistenceIdentity Identity(string name) =>
        PersistenceIdentity.FromEntry(Entries.Signed(AutostartVector.RunKey, name, @"C:\toy.exe"));

    private static PersistenceCoverageMap Coverage(string source) =>
        new(new Dictionary<string, IReadOnlyList<string>> { [source] = [] });

    [Fact]
    public void AnOldIncompatibleKernelObjectDoesNotControlSave() => BaselineFileFixture.Run(fixture =>
    {
        var key = Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(System.IO.Path.GetFullPath(fixture.Path).ToUpperInvariant())))[..32];
        using var incidental = new EventWaitHandle(false, EventResetMode.ManualReset,
            $@"Local\WinSight.PersistenceBaseline.{key}", out var created);
        Assert.True(created);
        var store = new FilePersistenceBaselineStore(fixture.Path);
        var expected = Identity("Independent");

        var failure = Record.Exception(() => store.Save([expected], Coverage("One")));

        Assert.Null(failure);
        var saved = Assert.IsType<PersistedBaseline>(store.LoadWithCoverage());
        Assert.Equal(expected, Assert.Single(saved.Identities));
        Assert.Equal("One", Assert.Single(saved.Coverage!.Sources).Key);
    });

    [Fact]
    public void AnUnrepresentableSidecarRefusesBeforeChangingTheBaseline() => BaselineFileFixture.Run(fixture =>
    {
        var path = System.IO.Path.Combine(fixture.Root, new string('a', 251));
        var previous = Encoding.UTF8.GetBytes("previous baseline");
        File.WriteAllBytes(path, previous);

        Assert.Throws<IOException>(() => new FilePersistenceBaselineStore(path).Save([Identity("New")]));

        Assert.Equal(previous, File.ReadAllBytes(path));
        Assert.Equal([path], Directory.GetFileSystemEntries(fixture.Root));
    });

    [Fact]
    public void ADirectoryAtTheSidecarIsARefusalAndPreservesThePreviousBytes() => BaselineFileFixture.Run(fixture =>
    {
        var previous = Encoding.UTF8.GetBytes("previous baseline");
        File.WriteAllBytes(fixture.Path, previous);
        Directory.CreateDirectory(fixture.Path + ".lock");

        Assert.Throws<IOException>(() => new FilePersistenceBaselineStore(fixture.Path).Save([Identity("New")]));

        Assert.Equal(previous, File.ReadAllBytes(fixture.Path));
        Assert.Empty(Directory.GetFileSystemEntries(fixture.Path + ".lock"));
    });

    [Fact]
    public void ConstructionAndMissingReadsDoNotCreateParentsOrSidecars() => BaselineFileFixture.Run(fixture =>
    {
        var parent = System.IO.Path.Combine(fixture.Root, "missing");
        var path = System.IO.Path.Combine(parent, "baseline.tsv");
        var store = new FilePersistenceBaselineStore(path);
        Assert.False(Directory.Exists(parent));
        Assert.Null(store.LoadWithCoverage());
        Assert.False(Directory.Exists(parent));

        store.Save([Identity("First")], Coverage("One"));

        Assert.True(File.Exists(path + ".lock"));
        Assert.Equal(Identity("First"), Assert.Single(store.Load()!));
    });

    [Fact]
    public void ReadingAnExistingBaselineDoesNotCreateASidecar() => BaselineFileFixture.Run(fixture =>
    {
        // Hand-written supported v3 fixture: this read must not first run a writer.
        File.WriteAllText(fixture.Path, "#winsight-guardian-baseline v3\n");

        Assert.Empty(new FilePersistenceBaselineStore(fixture.Path).Load()!);

        Assert.Equal([fixture.Path], Directory.GetFileSystemEntries(fixture.Root));
    });

    [Fact]
    public void EncodingFailureReleasesTheExistingGateWithoutPublishing() => BaselineFileFixture.Run(fixture =>
    {
        var store = new FilePersistenceBaselineStore(fixture.Path);
        store.Save([Identity("Previous")]);
        var previous = File.ReadAllBytes(fixture.Path);
        var failure = new InvalidOperationException("synthetic input enumeration failure");

        Assert.Same(failure, Record.Exception(() => store.Save(new ThrowingCollection(failure))));

        Assert.Equal(previous, File.ReadAllBytes(fixture.Path));
        using var gate = AutomaticFileAccess.TryAcquireExistingLockFile(fixture.Path + ".lock", out var status);
        Assert.Equal(LocalFileLockStatus.Acquired, status);
        Assert.NotNull(gate);
    });

    [Fact]
    public void PublicationRefusalReleasesTheGateAndPreservesTheDestination() => BaselineFileFixture.Run(fixture =>
    {
        Directory.CreateDirectory(fixture.Path);
        var sentinel = System.IO.Path.Combine(fixture.Path, "keep.txt");
        File.WriteAllText(sentinel, "keep");

        Assert.Throws<IOException>(() => new FilePersistenceBaselineStore(fixture.Path).Save([Identity("New")]));

        Assert.Equal("keep", File.ReadAllText(sentinel));
        using var gate = AutomaticFileAccess.TryAcquireExistingLockFile(fixture.Path + ".lock", out var status);
        Assert.Equal(LocalFileLockStatus.Acquired, status);
        Assert.NotNull(gate);
    });

    [Fact]
    public void ConcurrentWritersPublishOneCompleteSnapshotAndItsOwnCoverage() => BaselineFileFixture.Run(fixture =>
    {
        var release = fixture.NewEvent();
        var first = Identity("First");
        var second = Identity("Second");
        var a = fixture.StartWorker(() => Save(first, "A"));
        var b = fixture.StartWorker(() => Save(second, "B"));
        fixture.OnCleanup(release.Set);
        Assert.True(a.Entered.Wait(TimeSpan.FromSeconds(5)));
        Assert.True(b.Entered.Wait(TimeSpan.FromSeconds(5)));
        release.Set();
        Assert.True(a.Finished.Wait(TimeSpan.FromSeconds(5)));
        Assert.True(b.Finished.Wait(TimeSpan.FromSeconds(5)));
        Assert.Null(a.Failure);
        Assert.Null(b.Failure);

        var saved = Assert.IsType<PersistedBaseline>(new FilePersistenceBaselineStore(fixture.Path).LoadWithCoverage());
        var identity = Assert.Single(saved.Identities);
        Assert.True(identity == first || identity == second);
        Assert.Equal(identity == first ? "A" : "B", Assert.Single(saved.Coverage!.Sources).Key);

        void Save(PersistenceIdentity identity, string source)
        {
            if (!release.Wait(TimeSpan.FromSeconds(5))) { throw new TimeoutException("writer start gate"); }
            new FilePersistenceBaselineStore(fixture.Path).Save([identity], Coverage(source));
        }
    });

    private sealed class ThrowingCollection(Exception failure) : IReadOnlyCollection<PersistenceIdentity>
    {
        public int Count => 1;
        public IEnumerator<PersistenceIdentity> GetEnumerator() => throw failure;
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }
}

/// <summary>Owns toy paths, retained workers and their synchronization until checked termination.</summary>
internal sealed class BaselineFileFixture : IDisposable
{
    private readonly List<Worker> _workers = [];
    private readonly List<ManualResetEventSlim> _signals = [];
    private readonly List<Action> _cleanup = [];
    public string Root { get; } = Directory.CreateTempSubdirectory("winsight-baseline-").FullName;
    public string Path => System.IO.Path.Combine(Root, "baseline.tsv");

    public ManualResetEventSlim NewEvent()
    {
        var signal = new ManualResetEventSlim();
        _signals.Add(signal);
        return signal;
    }

    public void OnCleanup(Action action) => _cleanup.Add(action);

    public Worker StartWorker(Action action)
    {
        var worker = new Worker(action);
        _workers.Add(worker);
        worker.Start();
        return worker;
    }

    public static void Run(Action<BaselineFileFixture> action)
    {
        var fixture = new BaselineFileFixture();
        Exception? primary = null;
        try { action(fixture); }
        catch (Exception ex) { primary = ex; }
        try { fixture.Dispose(); }
        catch (Exception cleanup)
        {
            if (primary is not null) { throw new AggregateException(primary, cleanup); }
            throw;
        }
        if (primary is not null) { ExceptionDispatchInfo.Capture(primary).Throw(); }
    }

    public void Dispose()
    {
        List<Exception> errors = [];
        foreach (var action in _cleanup)
        {
            try { action(); }
            catch (Exception ex) { errors.Add(ex); }
        }
        var watch = Stopwatch.StartNew();
        foreach (var worker in _workers)
        {
            try
            {
                var remaining = TimeSpan.FromSeconds(5) - watch.Elapsed;
                if (!worker.Join(remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero))
                {
                    errors.Add(new TimeoutException("Baseline fixture worker did not terminate; its owned root is preserved."));
                }
            }
            catch (Exception ex) { errors.Add(ex); }
        }
        foreach (var worker in _workers)
        {
            if (!worker.IsAlive && worker.Failure is not null) { errors.Add(worker.Failure); }
        }
        if (_workers.Any(worker => worker.IsAlive))
        {
            throw new AggregateException(errors);
        }
        foreach (var worker in _workers)
        {
            worker.Dispose();
        }
        foreach (var signal in _signals) { signal.Dispose(); }
        try { Directory.Delete(Root, recursive: true); }
        catch (Exception ex) { errors.Add(ex); }
        if (errors.Count != 0) { throw new AggregateException(errors); }
    }

    internal sealed class Worker
    {
        private readonly Thread _thread;
        private bool _started;
        public ManualResetEventSlim Entered { get; } = new();
        public ManualResetEventSlim Finished { get; } = new();
        public Exception? Failure { get; private set; }
        public bool IsAlive => _started && _thread.IsAlive;
        public Worker(Action action) => _thread = new Thread(() =>
        {
            Entered.Set();
            try { action(); }
            catch (Exception ex) { Failure = ex; }
            finally { Finished.Set(); }
        })
        { IsBackground = true };
        public void Start() { _thread.Start(); _started = true; }
        public bool Join(TimeSpan wait) => !_started || _thread.Join(wait);
        public void Dispose() { Entered.Dispose(); Finished.Dispose(); }
    }
}

internal sealed class BaselineCountWitness(PersistenceIdentity identity, Action observeCount)
    : IReadOnlyCollection<PersistenceIdentity>
{
    public int Count { get { observeCount(); return 1; } }
    public IEnumerator<PersistenceIdentity> GetEnumerator() => ((IEnumerable<PersistenceIdentity>)[identity]).GetEnumerator();
    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
}
