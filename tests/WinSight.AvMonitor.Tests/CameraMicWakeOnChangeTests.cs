using System.Diagnostics;

using WinSight.AvMonitor;
using WinSight.Core;

using Xunit;

namespace WinSight.AvMonitor.Tests;

public sealed class CameraMicWakeOnChangeTests
{
    [Fact]
    public void TheWatchLoopWakesOnAChangeSignalWellBeforeThePollInterval()
    {
        var active = new DeviceUsage(DeviceKind.Webcam, @"C:\app\spy.exe", Packaged: false,
            DateTime.UtcNow, null, Active: true)
        { Store = CapabilityStore.CurrentUser };
        var reader = new StepReader(
            new CapabilityAccessSnapshot([], []),          // baseline: nothing active
            new CapabilityAccessSnapshot([active], []));    // after the wake: camera on
        var signal = new FakeSignal();
        using var stop = new CancellationTokenSource();
        using var activated = new ManualResetEventSlim(false);

        // A 30 s interval: if the loop only polled, the event could not arrive within the 5 s below.
        var monitor = new CameraMicMonitor(reader, TimeSpan.FromSeconds(30), () => signal);
        var thread = new Thread(() => monitor.Watch(
            e => { if (e.Kind == AvEventKind.Activated) { activated.Set(); } }, stop.Token))
        {
            IsBackground = true,
        };
        thread.Start();
        try
        {
            Assert.True(reader.FirstReadDone.Wait(TimeSpan.FromSeconds(5)), "the baseline read never happened");

            var sw = Stopwatch.StartNew();
            signal.Trigger();

            Assert.True(activated.Wait(TimeSpan.FromSeconds(5)), "the loop did not wake on the change signal");
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20), "the loop woke on the poll interval, not the signal");
        }
        finally
        {
            stop.Cancel();
            thread.Join(TimeSpan.FromSeconds(5));
        }

        Assert.True(signal.Disposed); // Watch owns the per-run signal and disposes it.
    }

    [Fact]
    public void AChangeSignalFactoryThatThrowsFallsBackToPollingInsteadOfBreakingTheWatch()
    {
        using var activated = new ManualResetEventSlim(false);
        using var stop = new CancellationTokenSource();
        var monitor = new CameraMicMonitor(ReaderTurningTheCameraOn(), TimeSpan.FromMilliseconds(50),
            () => throw new InvalidOperationException("signal unavailable"));

        RunUntil(monitor, stop, activated);

        Assert.True(activated.IsSet, "a faulting change signal stopped the poll that must still run");
    }

    [Fact]
    public void ASignalThatCannotStartIsDisposedAndThePollStillRuns()
    {
        var signal = new ThrowingStartSignal();
        using var activated = new ManualResetEventSlim(false);
        using var stop = new CancellationTokenSource();
        var monitor = new CameraMicMonitor(ReaderTurningTheCameraOn(), TimeSpan.FromMilliseconds(50), () => signal);

        RunUntil(monitor, stop, activated);

        Assert.True(activated.IsSet, "a signal that could not start stopped the poll");
        Assert.True(signal.Disposed, "the unusable signal was leaked instead of disposed");
    }

    private static StepReader ReaderTurningTheCameraOn()
    {
        var active = new DeviceUsage(DeviceKind.Webcam, @"C:\app\spy.exe", Packaged: false,
            DateTime.UtcNow, null, Active: true)
        { Store = CapabilityStore.CurrentUser };
        return new StepReader(new CapabilityAccessSnapshot([], []), new CapabilityAccessSnapshot([active], []));
    }

    private static void RunUntil(CameraMicMonitor monitor, CancellationTokenSource stop, ManualResetEventSlim activated)
    {
        var thread = new Thread(() => monitor.Watch(
            e => { if (e.Kind == AvEventKind.Activated) { activated.Set(); } }, stop.Token))
        {
            IsBackground = true,
        };
        thread.Start();
        try
        {
            activated.Wait(TimeSpan.FromSeconds(5));
        }
        finally
        {
            stop.Cancel();
            thread.Join(TimeSpan.FromSeconds(5));
        }
    }

    private sealed class ThrowingStartSignal : IChangeSignal
    {
        public bool Disposed { get; private set; }
        public WaitHandle? Start() => throw new UnauthorizedAccessException("hive is restricted");
        public void Dispose() => Disposed = true;
    }

    private sealed class StepReader(params CapabilityAccessSnapshot[] reads) : ICapabilityAccessReader
    {
        private int _next;

        public ManualResetEventSlim FirstReadDone { get; } = new(false);

        public AcquisitionSnapshot<DeviceUsage> ReadWithCoverage() => ReadWithProvenance().ToCoverage();

        public CapabilityAccessSnapshot ReadWithProvenance()
        {
            var read = reads[Math.Min(_next, reads.Length - 1)];
            _next++;
            if (_next == 1)
            {
                FirstReadDone.Set();
            }
            return read;
        }
    }

    private sealed class FakeSignal : IChangeSignal
    {
        private readonly AutoResetEvent _event = new(false);
        public bool Disposed { get; private set; }
        public WaitHandle? Start() => _event;
        public void Trigger() => _event.Set();
        public void Dispose() { Disposed = true; _event.Dispose(); }
    }
}
