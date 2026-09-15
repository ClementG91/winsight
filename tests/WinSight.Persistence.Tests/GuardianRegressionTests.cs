using WinSight.Core;

using Xunit;

namespace WinSight.Persistence.Tests;

public sealed class GuardianRegressionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    private static AutostartEntry Entry(string source = "Run keys") =>
        Entries.Unsigned(AutostartVector.RunKey, "Updater", @"C:\updater.exe") with
        {
            Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run [Registry64]",
            Source = source,
        };

    private static PersistenceScanResult Scan(string source, params AutostartEntry[] entries) =>
        new(entries, PersistenceCoverage.Complete, new HashSet<string> { source });

    [Theory]
    [InlineData("Updater", " Updater")]
    [InlineData("Updater", "Updater ")]
    [InlineData("Updater", "\"Updater\"")]
    [InlineData("A/B", "A\\B")]
    public void DistinctNamesAreNotNormalizedIntoOneEntry(string before, string after)
    {
        var core = new PersistenceMonitorCore();
        core.SeedBaseline([Entry() with { Name = before }]);

        Assert.Single(core.Reconcile([Entry() with { Name = after }], T0));
    }

    [Fact]
    public void LocationWhitespaceIsSignificant()
    {
        var original = Entry();
        Assert.NotEqual(PersistenceIdentity.FromEntry(original),
            PersistenceIdentity.FromEntry(original with { Location = original.Location + " " }));
    }

    [Fact]
    public void EveryBuiltInSourceCanConfirmAbsenceAfterItsOwnSuccessfulRead()
    {
        Assert.All(PersistenceScanner.DefaultEnumerators(), source => Assert.True(source.CanConfirmAbsence));
    }

    [Theory]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce [Registry64]")]
    [InlineData(@"HKLM\Software\Microsoft\Windows\CurrentVersion\Run [Registry64]")]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run [Registry32]")]
    public void DifferentPersistenceLocationsRaiseAnArrival(string location)
    {
        var original = Entry();
        var core = new PersistenceMonitorCore();
        core.SeedBaseline([original]);

        Assert.Single(core.Reconcile([original with { Location = location }], T0));
    }

    [Theory]
    [InlineData("rundll32.exe a.dll,Entry", "rundll32.exe a.dll,entry")]
    [InlineData("x.exe --name \"a  b\"", "x.exe --name \"a b\"")]
    [InlineData("x.exe -EncodedCommand AQAb", "x.exe -EncodedCommand AQab")]
    [InlineData("x.exe --data a\tb", "x.exe --data a b")]
    public void MeaningfulArgumentChangesRaiseAnArrival(string before, string after)
    {
        var original = Entry() with { Command = before };
        var core = new PersistenceMonitorCore();
        core.SeedBaseline([original]);

        Assert.Single(core.Reconcile([original with { Command = after }], T0));
    }

    [Fact]
    public void ConfirmedRemovalThenReappearanceNotifiesEvenWithAnUnacknowledgedEvent()
    {
        var entry = Entry();
        var core = new PersistenceMonitorCore();
        core.SeedBaseline([]);
        Assert.Single(core.Reconcile(Scan(entry.Source, entry), T0));
        Assert.Empty(core.Reconcile(Scan(entry.Source), T0.AddMinutes(1)));
        Assert.Empty(core.CurrentBaseline);

        var returned = Assert.Single(core.Reconcile(Scan(entry.Source, entry), T0.AddMinutes(2)));

        Assert.Equal(T0.AddMinutes(2), returned.FirstSeenUtc);
        Assert.Empty(core.Reconcile(Scan(entry.Source, entry), T0.AddMinutes(3)));
        Assert.Single(core.Log.Snapshot());
    }

    [Fact]
    public void ScopedCompleteScanDoesNotEraseAnotherSourceEvenWithTheSameVector()
    {
        var run = Entry();
        var otherUser = Entry("Other user hives") with { Location = @"HKU\S-1-5-21-123\Run" };
        var core = new PersistenceMonitorCore();
        core.SeedBaseline([run, otherUser]);

        core.Reconcile(Scan(run.Source), T0);

        Assert.Equal(PersistenceIdentity.FromEntry(otherUser), Assert.Single(core.CurrentBaseline));
        Assert.Empty(core.Reconcile(Scan(otherUser.Source, otherUser), T0.AddMinutes(1)));
        Assert.Single(core.Reconcile(Scan(run.Source, run), T0.AddMinutes(2)));
    }

    [Fact]
    public void PartialScanRetainsUnobservedEntriesWhileStillReportingNewOnes()
    {
        var known = Entry();
        var added = Entry() with { Name = "New" };
        var core = new PersistenceMonitorCore();
        core.SeedBaseline([known]);
        var partial = new PersistenceScanResult([added], new PersistenceCoverage(1, [known.Source]));

        Assert.Single(core.Reconcile(partial, T0));
        Assert.Equal(2, core.CurrentBaseline.Count);
        Assert.Empty(core.Reconcile(Scan(known.Source, known, added), T0.AddMinutes(1)));
    }

    [Fact]
    public void PartialStartupRetainsPersistedEntriesFromUnreadableSources()
    {
        var known = Entry();
        var core = new PersistenceMonitorCore();
        var partial = new PersistenceScanResult([], new PersistenceCoverage(1, [known.Source]));

        core.ReconcileFromPersistedBaseline(new HashSet<PersistenceIdentity>
            { PersistenceIdentity.FromEntry(known) }, partial, T0);

        Assert.Single(core.CurrentBaseline);
        Assert.Empty(core.Reconcile(Scan(known.Source, known), T0.AddMinutes(1)));
    }

    [Fact]
    public void BaselinePreservesSourceLocationAndRawMultilineArgumentPayload()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wsg-v3-{Guid.NewGuid():N}.tsv");
        var identity = PersistenceIdentity.FromEntry(Entry() with
        {
            Command = "powershell.exe -Command \"$Name = 'A  B'\r\nWrite-Output\t$Name\" ",
        });
        try
        {
            var store = new FilePersistenceBaselineStore(path);
            store.Save([identity]);

            Assert.Equal(identity, Assert.Single(store.Load()!));
            store.Save([]);
            Assert.NotNull(store.Load());
            Assert.Empty(store.Load()!);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ScannerOnlyCertifiesSourcesWithCompleteReliableReads()
    {
        var scan = new PersistenceScanner(
            [new FakeSurface("good", true), new FakeSurface("partial", true, unreadable: 1),
             new FakeSurface("unknown", false), new FakeSurface("failed", true, fail: true)],
            new NoSignatures()).ScanWithCoverage();

        Assert.Equal("good", Assert.Single(scan.CompleteSources!));
        Assert.Contains("partial", scan.Coverage.UnreadableSurfaces);
        Assert.Contains("failed", scan.Coverage.UnreadableSurfaces);
        Assert.Contains(scan.Entries, entry => entry.Source == "failed");
        Assert.Equal(4, scan.Entries.Select(entry => entry.Source).Distinct().Count());
    }

    private sealed class FakeSurface(string name, bool reliable, int unreadable = 0, bool fail = false)
        : IAutostartEnumerator
    {
        public string Surface => name;
        public bool CanConfirmAbsence => reliable;
        public int UnreadableLocations => unreadable;
        public IEnumerable<RawAutostart> Enumerate()
        {
            yield return new RawAutostart(AutostartVector.RunKey, name, @"HKCU\Run", @"C:\absent.exe");
            if (fail)
            {
                throw new UnauthorizedAccessException();
            }
        }
    }

    private sealed class NoSignatures : ISignatureVerifier
    {
        public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default) =>
            SignatureVerdict.Missing;
        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default) =>
            new Dictionary<string, SignatureVerdict>();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DisposeDoesNotWaitForADispatchingNotification(bool duringStartup)
    {
        var callbackEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseCallback = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var callbackExited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var source = new FakeChangeSource();
        var scans = 0;
        var entry = Entry();
        using var monitor = new PersistenceMonitor([], source, (_, _) =>
            Scan(entry.Source, duringStartup || Interlocked.Increment(ref scans) > 1 ? [entry] : []),
            debounce: TimeSpan.FromMilliseconds(1),
            baselineStore: new MemoryStore());
        monitor.Detected += (_, _) =>
        {
            callbackEntered.TrySetResult();
            releaseCallback.Task.GetAwaiter().GetResult();
            callbackExited.TrySetResult();
        };
        var starting = Task.Run(() => monitor.Start());
        try
        {
            if (!duringStartup)
            {
                await starting.WaitAsync(TimeSpan.FromSeconds(5));
                source.Signal();
            }
            await callbackEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

            await Task.Run(monitor.Dispose).WaitAsync(TimeSpan.FromSeconds(5));

            Assert.True(source.Disposed);
            Assert.False(monitor.IsStarted);
        }
        finally
        {
            releaseCallback.TrySetResult();
            await starting.WaitAsync(TimeSpan.FromSeconds(5));
            if (callbackEntered.Task.IsCompleted)
            {
                await callbackExited.Task.WaitAsync(TimeSpan.FromSeconds(5));
            }
        }
    }

    [Fact]
    public void StartupArmingFailureStillReportsDurablyReconciledArrivals()
    {
        var entry = Entry();
        var store = new MemoryStore();
        using var monitor = new PersistenceMonitor([], new FakeChangeSource(failStart: true),
            (_, _) => Scan(entry.Source, entry), baselineStore: store);
        var arrivals = new List<PersistenceEvent>();
        monitor.Detected += (_, args) => arrivals.Add(args.Detected);

        Assert.Throws<IOException>(() => monitor.Start());

        Assert.Single(arrivals);
        Assert.Contains(PersistenceIdentity.FromEntry(entry), store.Load());
        Assert.False(monitor.IsStarted);
    }

    private sealed class FakeChangeSource(bool failStart = false) : IPersistenceChangeSource
    {
        public bool Disposed { get; private set; }
        public event EventHandler<PersistenceSurfaceChangedEventArgs>? SurfaceChanged;
        public void Signal() => SurfaceChanged?.Invoke(this, new PersistenceSurfaceChangedEventArgs([]));
        public void Start()
        {
            if (failStart)
            {
                throw new IOException("Watcher arming failed");
            }
        }
        public void Dispose() => Disposed = true;
    }

    private sealed class MemoryStore : IPersistenceBaselineStore
    {
        private IReadOnlySet<PersistenceIdentity> _baseline = new HashSet<PersistenceIdentity>();
        public IReadOnlySet<PersistenceIdentity> Load() => _baseline;
        public void Save(IReadOnlyCollection<PersistenceIdentity> baseline) => _baseline = baseline.ToHashSet();
    }
}
