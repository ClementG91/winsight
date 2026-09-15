using WinSight.AvMonitor;
using WinSight.Core;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// Lifecycle only. The detection itself — which transitions count as an activation — is a pure diff
/// already covered in the AvMonitor tests; what is new here is the host that keeps a blocking poll
/// loop running for the life of the dashboard, so the risks worth pinning are a leaked polling
/// thread and an unsafe second call.
/// </summary>
public sealed class AvWatchHostTests
{
    [Fact]
    public void Dispose_StopsWatchingPromptly()
    {
        var host = new AvWatchHost();
        host.Start();

        // A poll loop that ignored cancellation would keep a thread alive for the whole process.
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        host.Dispose();
        stopwatch.Stop();

        Assert.True(
            stopwatch.Elapsed < TimeSpan.FromSeconds(5),
            $"Dispose blocked for {stopwatch.Elapsed}, which suggests it waits on the poll interval.");
    }

    [Fact]
    public void Start_IsIdempotent()
    {
        // The dashboard starts monitoring from a lifecycle event that can fire more than once; a
        // second call must not leave a second poll loop running behind the first.
        using var host = new AvWatchHost();

        host.Start();
        host.Start();
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var host = new AvWatchHost();
        host.Start();

        host.Dispose();
        host.Dispose();
    }

    [Fact]
    public void Start_AfterDispose_DoesNothing()
    {
        // Shutdown order is not guaranteed: a late start must not resurrect the loop after the
        // window has gone.
        var host = new AvWatchHost();
        host.Dispose();

        host.Start();
    }

    [Fact]
    public void DisposeWithoutStart_IsSafe()
    {
        // The dashboard disposes its monitors unconditionally, including when startup failed early.
        var host = new AvWatchHost();

        host.Dispose();
    }

    [Fact]
    public void AnAppTakingTheMicrophoneReachesTheSubscriber()
    {
        // The end-to-end claim: a device goes live and whoever is listening is told, with the app
        // named. Until the reader was put behind an interface this could not be tested at all —
        // it needed real hardware, so a machine with no webcam (every CI runner, and this one)
        // could never exercise the alerting path the whole feature exists for.
        var reader = new ScriptedReader(
            [Idle],
            [InUse]);
        using var host = new AvWatchHost(new CameraMicMonitor(reader, TimeSpan.FromMilliseconds(15)));
        using var raised = new ManualResetEventSlim();
        DeviceEvent? observed = null;
        host.Detected += (_, e) =>
        {
            observed = e;
            raised.Set();
        };

        host.Start();

        Assert.True(raised.Wait(TimeSpan.FromSeconds(10)), "No activation reached the subscriber.");
        Assert.Equal(AvEventKind.Activated, observed!.Kind);
        Assert.Equal(DeviceKind.Microphone, observed.Usage.Kind);
        Assert.Equal(@"C:\apps\recorder.exe", observed.Usage.App);
    }

    /// <summary>
    /// Regression guard for the defect that failed the v0.10.5 release build on 2026-07-27.
    /// </summary>
    /// <remarks>
    /// The watch loop blocks until shutdown. Parking it on the thread pool held a pool thread for the
    /// life of the dashboard <b>and</b> left the loop itself queued behind a saturated pool, waiting
    /// seconds for a thread it would then never give back. The end-to-end test above only saw that as
    /// an occasional timeout — a symptom that reads as flakiness and invites a re-run. This asserts
    /// the property directly, so the defect cannot come back disguised as an intermittent failure.
    /// </remarks>
    [Fact]
    public void TheWatchLoopDoesNotRunOnAThreadPoolThread()
    {
        using var polled = new ManualResetEventSlim();
        var onPoolThread = true;
        var reader = new ThreadRecordingReader(() =>
        {
            onPoolThread = Thread.CurrentThread.IsThreadPoolThread;
            polled.Set();
        });
        using var host = new AvWatchHost(new CameraMicMonitor(reader, TimeSpan.FromMilliseconds(15)));

        host.Start();

        Assert.True(polled.Wait(TimeSpan.FromSeconds(10)), "The poll loop never ran at all.");
        Assert.False(
            onPoolThread,
            "The watch loop is running on a thread-pool thread. It blocks until shutdown, so it holds "
            + "that thread for the life of the process and starves every other pool user.");
    }

    /// <summary>
    /// A fault in the watch loop stops the watcher, never the process.
    /// </summary>
    /// <remarks>
    /// Moving this loop off the thread pool changed what an unhandled exception costs. A pool work
    /// item that throws produces an unobserved task exception the runtime ignores; a dedicated thread
    /// that throws terminates the process. The handler listed three exception types, which was
    /// adequate under the old model and meant a camera-watcher fault could take the whole dashboard
    /// down and every other monitor with it. On 2026-07-30 that crashed a CI test host mid-run.
    ///
    /// A real activation must reach the throwing subscriber; an empty reader never exercised
    /// this fault. The failure is contained per handler: the other handler still receives the event,
    /// the watch keeps polling (a second activation still arrives), and the fault is visible as a
    /// partial monitor. Stopping the whole watch for one faulty consumer blinded camera/microphone
    /// monitoring for the rest of the session.
    /// </remarks>
    [Fact]
    public void AThrowingSubscriberIsContainedAndTheWatchContinues()
    {
        using var healthyReceivedTwo = new ManualResetEventSlim();
        var later = InUse with { LastStart = SessionStart.AddMinutes(1) };
        var reader = new ScriptedReader([Idle], [InUse], [Idle], [later]);
        var host = new AvWatchHost(new CameraMicMonitor(reader, TimeSpan.FromMilliseconds(15)));
        host.Detected += (_, _) => throw new InvalidOperationException("a subscriber fault");
        var healthy = 0;
        host.Detected += (_, e) =>
        {
            if (e.Kind == AvEventKind.Activated && Interlocked.Increment(ref healthy) == 2)
            {
                healthyReceivedTwo.Set();
            }
        };

        host.Start();

        Assert.True(healthyReceivedTwo.Wait(TimeSpan.FromSeconds(10)), "The watch stopped after the subscriber fault.");
        Assert.True(host.Status.IsRunning);
        Assert.Null(host.Status.Failure);
        Assert.True(host.Status.NotificationFailures >= 2);
        Assert.IsType<InvalidOperationException>(host.Status.LastNotificationFailure);
        Assert.Equal(ProtectionState.Partial, host.Health(enabled: true).State);
        host.Dispose();
        host.Dispose();
    }

    [Fact]
    public void AnUnexpectedReaderFaultIsVisibleThenRecoveredByABoundedRestart()
    {
        var reader = new FaultThenWorkReader(faults: 1);
        using var host = new AvWatchHost(new CameraMicMonitor(reader, TimeSpan.FromMilliseconds(10)),
            [TimeSpan.FromMilliseconds(50)]);

        host.Start();

        Assert.True(WaitUntil(() => host.Status is { IsRunning: true, HasSnapshot: true, Restarts: 1 }));
        Assert.Null(host.Status.Failure);
        Assert.Equal(ProtectionState.Active, host.Health(enabled: true).State);
    }

    [Fact]
    public void RestartsStopAfterTheBudgetAndStayFailed()
    {
        var reader = new FaultThenWorkReader(faults: int.MaxValue);
        using var host = new AvWatchHost(new CameraMicMonitor(reader, TimeSpan.FromMilliseconds(10)),
            [TimeSpan.FromMilliseconds(20), TimeSpan.FromMilliseconds(20)]);

        host.Start();

        Assert.True(WaitUntil(() => host.Status.RestartsExhausted));
        Thread.Sleep(150); // no further restarts
        Assert.Equal(2, host.Status.Restarts);
        Assert.Equal(3, reader.Calls);
        Assert.Equal(ProtectionState.Failed, host.Health(enabled: true).State);
    }

    /// <summary>
    /// Restarts are scheduled on a thread-pool timer, which parallel test classes can delay by seconds.
    /// This is a hang detector: it sleeps rather than spins so it does not compete for the same cores.
    /// </summary>
    private static bool WaitUntil(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(60);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                return false;
            }
            Thread.Sleep(20);
        }
        return true;
    }

    private sealed class FaultThenWorkReader(int faults) : ICapabilityAccessReader
    {
        private int _calls;
        public int Calls => Volatile.Read(ref _calls);
        public AcquisitionSnapshot<DeviceUsage> ReadWithCoverage() =>
            Interlocked.Increment(ref _calls) <= faults
                ? throw new InvalidOperationException("unexpected reader fault")
                : new AcquisitionSnapshot<DeviceUsage>([]);
    }
    [Fact]
    public void ADeviceAlreadyInUseAtStartupIsNotReportedAsNew()
    {
        // The first snapshot is a baseline, exactly like Guardian's. Something already holding the
        // microphone when the dashboard opens is the status quo, not an event — reporting it would
        // cry wolf on every launch during a call.
        var reader = new ScriptedReader(
            [InUse],
            [InUse]);
        using var host = new AvWatchHost(new CameraMicMonitor(reader, TimeSpan.FromMilliseconds(15)));
        using var raised = new ManualResetEventSlim();
        host.Detected += (_, _) => raised.Set();

        host.Start();

        Assert.False(raised.Wait(TimeSpan.FromMilliseconds(400)), "A pre-existing session was reported as new.");
    }

    // Windows keeps LastUsedTimeStart fixed for the life of one capture session; a new value is a restart.
    private static readonly DateTime SessionStart = DateTime.UtcNow.AddMinutes(-1);

    private static DeviceUsage InUse => new(
        DeviceKind.Microphone, @"C:\apps\recorder.exe", Packaged: false, LastStart: SessionStart,
        LastStop: null, Active: true);

    private static DeviceUsage Idle => InUse with { Active = false, LastStop = DateTime.UtcNow };

    /// <summary>
    /// Returns each scripted snapshot in turn, then repeats the last one, so the poll loop keeps
    /// running without the test having to script every tick.
    /// </summary>
    private sealed class ScriptedReader(params IReadOnlyList<DeviceUsage>[] snapshots) : ICapabilityAccessReader
    {
        private int _index;

        public AcquisitionSnapshot<DeviceUsage> ReadWithCoverage()
        {
            var current = snapshots[Math.Min(_index, snapshots.Length - 1)];
            _index++;
            return new AcquisitionSnapshot<DeviceUsage>(current);
        }
    }

    /// <summary>Reports which thread the poll loop is actually running on, once, on its first read.</summary>
    private sealed class ThreadRecordingReader(Action onFirstRead) : ICapabilityAccessReader
    {
        private int _reads;

        public AcquisitionSnapshot<DeviceUsage> ReadWithCoverage()
        {
            if (Interlocked.Increment(ref _reads) == 1)
            {
                onFirstRead();
            }
            return new AcquisitionSnapshot<DeviceUsage>([]);
        }
    }
}
