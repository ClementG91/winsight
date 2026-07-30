using WinSight.NetMonitor;
using Xunit;

namespace WinSight.Attribution.Tests;

/// <summary>
/// The seam between the session that observes writes and the index that remembers them. Driven by
/// a scripted watcher, so the join — and the health reporting that says whether an empty answer
/// means "nothing wrote this" or "nobody was watching" — is exercised without Administrator.
/// </summary>
public sealed class AttributionHostTests
{
    private static readonly DateTimeOffset Noon = new(2026, 7, 21, 12, 0, 0, TimeSpan.Zero);
    private const string RunKey = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

    [Fact]
    public void AnObservedWriteBecomesAnAnswer()
    {
        var watcher = new ScriptedWatcher(
            writes: [new WriteObservation(Noon, 4242, @"C:\tmp\dropper.exe", RunKey)]);
        using var host = new AttributionHost(watcher);

        host.Start();
        watcher.Delivered.Wait(TimeSpan.FromSeconds(5));

        var attributed = host.Attribute($"{RunKey} [Updater]", Noon.AddSeconds(1));
        Assert.Equal(@"C:\tmp\dropper.exe", attributed?.ExecutablePath);
    }

    [Fact]
    public void HealthDistinguishesBlindFromIdle()
    {
        // The distinction the whole type exists for: "running and saw twelve it could not pin"
        // is a completely different message to an operator than "not watching at all".
        var watcher = new ScriptedWatcher(
            writes: [new WriteObservation(Noon, 1, @"C:\a.exe", RunKey)],
            misses:
            [
                new UnattributedWrite(Noon, 2, RunKey, UnattributedReason.UnknownProcess),
                new UnattributedWrite(Noon, 3, null, UnattributedReason.UnresolvedTarget),
                new UnattributedWrite(Noon, 4, null, UnattributedReason.UnresolvedTarget),
            ]);
        using var host = new AttributionHost(watcher);

        host.Start();
        watcher.Delivered.Wait(TimeSpan.FromSeconds(5));

        var health = host.Health;
        Assert.Equal(1, health.Attributed);
        Assert.Equal(1, health.UnknownProcess);
        Assert.Equal(2, health.UnannouncedKey);
        Assert.Equal(3, health.Unattributed);
        Assert.False(health.Refused);
    }

    [Fact]
    public void HealthSeparatesAnUnannouncedKeyFromAnUntranslatablePath()
    {
        // Both are "a write nobody could name", and merging them makes either impossible to
        // investigate: an unannounced handle is a gap in the kernel's bookkeeping replay, an
        // untranslatable path is a gap in WinSight's own namespace mapping. Different fixes.
        var watcher = new ScriptedWatcher(
            misses:
            [
                new UnattributedWrite(Noon, 1, null, UnattributedReason.UnresolvedTarget),
                new UnattributedWrite(
                    Noon, 2, @"\REGISTRY\A\{a-packaged-app}", UnattributedReason.UnresolvedTarget),
            ]);
        using var host = new AttributionHost(watcher);

        host.Start();
        watcher.Delivered.Wait(TimeSpan.FromSeconds(5));

        var health = host.Health;
        Assert.Equal(1, health.UnannouncedKey);
        Assert.Equal(1, health.UntranslatablePath);
    }

    [Fact]
    public void NotBeingElevatedIsRecordedAsARefusalNotAsSilence()
    {
        // Without this, "attribution is unavailable" and "nothing wrote to that key" are the same
        // empty answer, and an operator cannot tell a quiet machine from a monitor that never ran.
        var watcher = new ScriptedWatcher(refuse: true);
        using var host = new AttributionHost(watcher);

        host.Start();
        watcher.Delivered.Wait(TimeSpan.FromSeconds(5));
        SpinWait.SpinUntil(() => host.Health.Refused, TimeSpan.FromSeconds(5));

        Assert.True(host.Health.Refused);
        Assert.False(host.Health.Running);
        Assert.Null(host.Attribute(RunKey, Noon));
    }

    [Fact]
    public void AnUnwatchedTargetHasNoAnswer()
    {
        var watcher = new ScriptedWatcher(
            writes: [new WriteObservation(Noon, 1, @"C:\a.exe", @"HKLM\SOFTWARE\Something")]);
        using var host = new AttributionHost(watcher);

        host.Start();
        watcher.Delivered.Wait(TimeSpan.FromSeconds(5));

        Assert.Null(host.Attribute(RunKey, Noon.AddSeconds(1)));
    }

    [Fact]
    public void StartIsIdempotent()
    {
        var watcher = new ScriptedWatcher();
        using var host = new AttributionHost(watcher);

        host.Start();
        host.Start();

        Assert.True(watcher.Starts <= 1, $"Watch was started {watcher.Starts} times.");
    }

    [Fact]
    public void DisposeStopsTheWatchPromptly()
    {
        var watcher = new ScriptedWatcher(blockUntilCancelled: true);
        var host = new AttributionHost(watcher);
        host.Start();

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        host.Dispose();
        stopwatch.Stop();

        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5), $"Dispose took {stopwatch.Elapsed}.");
    }

    [Fact]
    public void StartAfterDisposeDoesNothing()
    {
        var watcher = new ScriptedWatcher();
        var host = new AttributionHost(watcher);
        host.Dispose();

        host.Start();

        Assert.Equal(0, watcher.Starts);
    }

    [Fact]
    public void AttributionHealthRetainsItsSixValuePublicRecordContract()
    {
        var constructor = typeof(AttributionHealth).GetConstructor(
            [typeof(bool), typeof(long), typeof(long), typeof(long), typeof(long), typeof(bool)]);
        Assert.NotNull(constructor);
        Assert.Contains(
            typeof(AttributionHealth).GetMethods(),
            method => method.Name == "Deconstruct" && method.GetParameters().Length == 6);

        var health = new AttributionHealth(
            Running: false,
            Attributed: 1,
            UnknownProcess: 2,
            UnannouncedKey: 3,
            UntranslatablePath: 4,
            Refused: false);
        var (running, attributed, unknownProcess, unannouncedKey, untranslatablePath, refused) = health;

        Assert.False(running);
        Assert.Equal((1L, 2L, 3L, 4L, false),
            (attributed, unknownProcess, unannouncedKey, untranslatablePath, refused));
    }

    [Theory]
    [InlineData(unchecked((int)0x800705AA), (int)EtwFailureCode.ResourceExhausted)] // ERROR_NO_SYSTEM_RESOURCES
    [InlineData(unchecked((int)0x800700B7), (int)EtwFailureCode.SessionCollision)] // ERROR_ALREADY_EXISTS
    public void AnOperationalEtwComFailureStopsOnlyAttribution(int hresult, int expectedFailure)
    {
        // This must run entirely through the watcher seam: opening a real ETW session here would
        // make the portable unit suite consume a machine-global, privileged resource. Both quota
        // exhaustion and a session-name collision must degrade attribution rather than terminate
        // the dashboard process that owns this background thread.
        var watcher = new ScriptedWatcher(
            failure: EtwFailure(hresult));
        using var host = new AttributionHost(watcher);

        host.Start();

        Assert.True(watcher.Completed.Wait(TimeSpan.FromSeconds(5)));
        Assert.True(SpinWait.SpinUntil(() => !host.Health.Running, TimeSpan.FromSeconds(5)));
        Assert.False(host.Health.Running);
        Assert.False(host.Health.Refused);
        Assert.Equal((EtwFailureCode)expectedFailure, host.Health.Failure);
    }

    [Fact]
    public void AWin32AccessDeniedFailureIsClassifiedWithoutClaimingTheWatcherIsStillRunning()
    {
        var watcher = new ScriptedWatcher(failure: new System.ComponentModel.Win32Exception(5));
        using var host = new AttributionHost(watcher);

        host.Start();

        Assert.True(watcher.Completed.Wait(TimeSpan.FromSeconds(5)));
        Assert.True(SpinWait.SpinUntil(() => !host.Health.Running, TimeSpan.FromSeconds(5)));
        Assert.False(host.Health.Refused);
        Assert.Equal(EtwFailureCode.AccessDenied, host.Health.Failure);
    }

    [Fact]
    public void AnUnexpectedNonfatalWatcherFailureDoesNotEscapeTheWorkerThread()
    {
        // A future TraceEvent failure type must not turn into a process-wide unhandled exception.
        // This assertion deliberately uses an exception outside the known ETW HRESULT list.
        var watcher = new ScriptedWatcher(failure: new InvalidOperationException("test-only"));
        using var host = new AttributionHost(watcher);

        host.Start();

        Assert.True(watcher.Completed.Wait(TimeSpan.FromSeconds(5)));
        Assert.True(SpinWait.SpinUntil(() => !host.Health.Running, TimeSpan.FromSeconds(5)));
        Assert.False(host.Health.Refused);
        Assert.Equal(EtwFailureCode.Unexpected, host.Health.Failure);
    }

    [Fact]
    public void CancellationRequestedByDisposeIsNotReportedAsAnElevationRefusal()
    {
        var watcher = new ScriptedWatcher(blockUntilCancelled: true);
        var host = new AttributionHost(watcher);
        host.Start();

        host.Dispose();

        Assert.True(watcher.Completed.Wait(TimeSpan.FromSeconds(5)));
        Assert.False(host.Health.Running);
        Assert.False(host.Health.Refused);
        Assert.Equal(EtwFailureCode.None, host.Health.Failure);
    }

    [Fact]
    public void AnUnrequestedCancellationIsAnUnexpectedFailureNotANormalShutdown()
    {
        var watcher = new ScriptedWatcher(failure: new OperationCanceledException("not requested"));
        using var host = new AttributionHost(watcher);

        host.Start();

        Assert.True(watcher.Completed.Wait(TimeSpan.FromSeconds(5)));
        Assert.True(SpinWait.SpinUntil(() => !host.Health.Running, TimeSpan.FromSeconds(5)));
        Assert.Equal(EtwFailureCode.Unexpected, host.Health.Failure);
        Assert.False(host.Health.Refused);
    }

    private sealed class ScriptedWatcher(
        IReadOnlyList<WriteObservation>? writes = null,
        IReadOnlyList<UnattributedWrite>? misses = null,
        bool refuse = false,
        bool blockUntilCancelled = false,
        Exception? failure = null) : IWriteWatcher
    {
        private int _starts;

        public int Starts => Volatile.Read(ref _starts);

        public ManualResetEventSlim Delivered { get; } = new();

        public ManualResetEventSlim Completed { get; } = new();

        public void Watch(
            Action<WriteObservation> onWrite,
            Action<UnattributedWrite>? onUnattributed,
            CancellationToken token)
        {
            Interlocked.Increment(ref _starts);
            try
            {
                if (refuse)
                {
                    Delivered.Set();
                    throw new UnauthorizedAccessException("elevation required");
                }

                foreach (var write in writes ?? [])
                {
                    onWrite(write);
                }
                foreach (var miss in misses ?? [])
                {
                    onUnattributed?.Invoke(miss);
                }
                Delivered.Set();

                if (blockUntilCancelled)
                {
                    token.WaitHandle.WaitOne();
                    token.ThrowIfCancellationRequested();
                }

                if (failure is not null)
                {
                    throw failure;
                }
            }
            finally
            {
                Completed.Set();
            }
        }
    }

    private static Exception EtwFailure(int hresult)
    {
        try
        {
            System.Runtime.InteropServices.Marshal.ThrowExceptionForHR(hresult);
        }
        catch (UnauthorizedAccessException failure)
        {
            return failure;
        }
        catch (System.Runtime.InteropServices.COMException failure)
        {
            return failure;
        }

        throw new InvalidOperationException($"HRESULT 0x{hresult:X8} did not produce a COM exception.");
    }
}
