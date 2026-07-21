using WinSight.AvMonitor;

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

    private static DeviceUsage InUse => new(
        DeviceKind.Microphone, @"C:\apps\recorder.exe", Packaged: false, LastStart: DateTime.UtcNow,
        LastStop: null, Active: true);

    private static DeviceUsage Idle => InUse with { Active = false, LastStop = DateTime.UtcNow };

    /// <summary>
    /// Returns each scripted snapshot in turn, then repeats the last one, so the poll loop keeps
    /// running without the test having to script every tick.
    /// </summary>
    private sealed class ScriptedReader(params IReadOnlyList<DeviceUsage>[] snapshots) : ICapabilityAccessReader
    {
        private int _index;

        public IReadOnlyList<DeviceUsage> Read()
        {
            var current = snapshots[Math.Min(_index, snapshots.Length - 1)];
            _index++;
            return current;
        }
    }
}
