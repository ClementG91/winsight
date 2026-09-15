using Microsoft.Win32;

using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// Integration risks left open by the Guardian corrections: shutdown during a scan, arrivals that
/// were reconciled but never delivered, and read failures that were swallowed while the source
/// still claimed it could prove absence.
/// </summary>
public sealed class GuardianDeliveryAndEvidenceTests
{
    private static AutostartEntry Entry() =>
        Entries.Unsigned(AutostartVector.RunKey, "Updater", @"C:\updater.exe") with
        {
            Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run [Registry64]",
            Source = "Run keys",
        };

    private static PersistenceScanResult Scan(params AutostartEntry[] entries) =>
        new(entries, PersistenceCoverage.Complete, new HashSet<string> { "Run keys" });

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task DisposeCancelsAnInFlightScanInsteadOfWaitingForIt(bool duringStartup)
    {
        var scanEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var scans = 0;
        var source = new SignalSource();
        var monitor = new PersistenceMonitor([], source, (_, token) =>
        {
            if (duringStartup || Interlocked.Increment(ref scans) > 1)
            {
                scanEntered.TrySetResult();
                // A real full rescan verifies thousands of signatures; only cancellation ends it.
                token.WaitHandle.WaitOne(TimeSpan.FromSeconds(30));
                token.ThrowIfCancellationRequested();
            }
            return Scan();
        }, debounce: TimeSpan.FromMilliseconds(1), baselineStore: new MemoryStore());

        var starting = Task.Run(() => monitor.Start());
        if (!duringStartup)
        {
            await starting.WaitAsync(TimeSpan.FromSeconds(5));
            source.Signal();
        }
        await scanEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        await Task.Run(monitor.Dispose).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.True(source.Disposed);
        if (duringStartup)
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => starting);
        }
    }

    [Fact]
    public void AnArrivalWhoseSubscriberFailedIsReportedAgainOnTheNextLaunch()
    {
        var entry = Entry();
        var store = new MemoryStore();
        store.Save([]); // a previous run's baseline, so this start reconciles instead of seeding
        using (var first = new PersistenceMonitor([], new SignalSource(), (_, _) => Scan(entry),
                   baselineStore: store))
        {
            first.Detected += (_, _) => throw new InvalidOperationException("journal unavailable");
            // Contained at the monitor boundary: the arrival stays pending and visible, not thrown.
            first.Start();
            Assert.Equal(1, first.Diagnostics.PendingNotifications);
            Assert.Equal(PersistenceMonitorOperation.Notification, first.Diagnostics.LastFault!.Operation);
        }

        Assert.DoesNotContain(PersistenceIdentity.FromEntry(entry), store.Load()!);
        using var second = new PersistenceMonitor([], new SignalSource(), (_, _) => Scan(entry),
            baselineStore: store);
        var arrivals = new List<PersistenceEvent>();
        second.Detected += (_, e) => arrivals.Add(e.Detected);
        second.Start();

        Assert.Single(arrivals);
        second.Dispose();
        Assert.Contains(PersistenceIdentity.FromEntry(entry), store.Load()!);
    }

    [Fact]
    public async Task ShutdownDuringAReconcileNeverAcknowledgesTheUnreportedArrival()
    {
        var entry = Entry();
        var store = new MemoryStore();
        var source = new SignalSource();
        PersistenceMonitor? monitor = null;
        Task? disposing = null;
        var scans = 0;
        monitor = new PersistenceMonitor([], source, (_, _) =>
        {
            if (Interlocked.Increment(ref scans) == 1)
            {
                return Scan();
            }
            // The operator closes the dashboard while the change scan is finishing.
            disposing = Task.Run(monitor!.Dispose, CancellationToken.None);
            SpinWait.SpinUntil(() => !monitor.IsStarted, TimeSpan.FromSeconds(5));
            return Scan(entry);
        }, debounce: TimeSpan.FromMilliseconds(1), baselineStore: store);
        var arrivals = 0;
        monitor.Detected += (_, _) => Interlocked.Increment(ref arrivals);
        monitor.Start();

        source.Signal();
        SpinWait.SpinUntil(() => disposing is not null, TimeSpan.FromSeconds(5));
        await disposing!.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, arrivals);
        Assert.DoesNotContain(PersistenceIdentity.FromEntry(entry), store.Load()!);
    }

    [Fact]
    public void ScheduledTaskCollectionReportsDeniedFoldersAndUnreadableTasks()
    {
        var root = new FakeFolder(
            [new FakeTask(@"\Visible", "<Task/>")],
            [new FakeFolder(deny: true), new FakeFolder([new FakeTask(@"\Protected\Task", null)], [])]);
        var collected = new List<ScheduledTaskDefinition>();

        Assert.False(ComScheduledTaskSource.Collect(root, collected, depth: 0));
        Assert.Equal(@"\Visible", Assert.Single(collected).Path);

        var readable = new List<ScheduledTaskDefinition>();
        Assert.True(ComScheduledTaskSource.Collect(
            new FakeFolder([new FakeTask(@"\A", "<Task/>")], []), readable, depth: 0));
    }

    [Fact]
    public void DeniedClassOverrideIsUnreadableRatherThanTheMachineRegistration()
    {
        var resolved = ClsidResolver.TryResolveInprocServer("{0000-test}", RegistryView.Registry64,
            out var path,
            (hive, _, _, _) => hive == RegistryHive.CurrentUser
                ? throw new UnauthorizedAccessException()
                : @"C:\Windows\System32\legit.dll");

        Assert.False(resolved);
        Assert.Null(path);
        Assert.True(ClsidResolver.TryResolveInprocServer("{0000-test}", RegistryView.Registry64,
            out var machine, (hive, _, _, subKey) =>
                hive == RegistryHive.LocalMachine && subKey == "InprocServer32" ? @"C:\legit.dll" : null));
        Assert.Equal(@"C:\legit.dll", machine);
    }

    public sealed class FakeTask(string path, string? xml)
    {
        public string Path { get; } = path;
        public string? Xml => xml ?? throw new UnauthorizedAccessException("task definition denied");
    }

    public sealed class FakeFolder(IReadOnlyList<FakeTask>? tasks = null,
        IReadOnlyList<FakeFolder>? folders = null, bool deny = false)
    {
        public IEnumerable<FakeTask> GetTasks(int flags) =>
            deny ? throw new UnauthorizedAccessException("folder denied") : tasks ?? [];

        public IEnumerable<FakeFolder> GetFolders(int flags) => folders ?? [];
    }

    private sealed class SignalSource : IPersistenceChangeSource
    {
        public bool Disposed { get; private set; }
        public event EventHandler<PersistenceSurfaceChangedEventArgs>? SurfaceChanged;
        public void Signal() => SurfaceChanged?.Invoke(this, new PersistenceSurfaceChangedEventArgs([]));
        public void Start()
        {
        }
        public void Dispose() => Disposed = true;
    }

    private sealed class MemoryStore : IPersistenceBaselineStore
    {
        private IReadOnlySet<PersistenceIdentity>? _baseline;
        public IReadOnlySet<PersistenceIdentity>? Load() => _baseline;
        public void Save(IReadOnlyCollection<PersistenceIdentity> baseline) => _baseline = baseline.ToHashSet();
    }
}
