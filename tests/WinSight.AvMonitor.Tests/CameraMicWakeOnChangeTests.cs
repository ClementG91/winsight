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

        // A 30 s interval: if the loop only polled, the event could not arrive within the 15 s below.
        var monitor = new CameraMicMonitor(reader, TimeSpan.FromSeconds(30), () => signal);
        var thread = new Thread(() => monitor.Watch(
            e => { if (e.Kind == AvEventKind.Activated) { activated.Set(); } }, stop.Token))
        {
            IsBackground = true,
        };
        thread.Start();
        try
        {
            Assert.True(reader.FirstReadDone.Wait(TimeSpan.FromSeconds(30)), "the baseline read never happened");

            var sw = Stopwatch.StartNew();
            signal.Trigger();

            Assert.True(activated.Wait(TimeSpan.FromSeconds(15)), "the loop did not wake on the change signal");
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20), "the loop woke on the poll interval, not the signal");
        }
        finally
        {
            stop.Cancel();
            thread.Join(TimeSpan.FromSeconds(30));
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

    /// <summary>
    /// Each poll reads the whole consent store; at one a second an idle watch cost about 1.7% of a
    /// core. While the signal vouches for every hive it watches, the fallback poll is the slow one.
    /// </summary>
    [Fact]
    public void AnObservingSignalSlowsTheFallbackPoll()
    {
        var reader = new CountingReader();
        var signal = new FakeSignal { Observing = true };
        var monitor = new CameraMicMonitor(
            reader, TimeSpan.FromMilliseconds(20), () => signal, observedInterval: TimeSpan.FromSeconds(30));

        RunFor(monitor, TimeSpan.FromMilliseconds(600));

        Assert.InRange(reader.Reads, 1, 2);
    }

    /// <summary>
    /// The moment the signal cannot vouch for itself - a watch that stopped re-arming - the loop is
    /// back on the fast poll, so detection never waits on a silent watch.
    /// </summary>
    [Fact]
    public void ASignalThatStopsVouchingRestoresTheFastPoll()
    {
        var reader = new CountingReader();
        var signal = new FakeSignal { Observing = true };
        var monitor = new CameraMicMonitor(
            reader, TimeSpan.FromMilliseconds(20), () => signal, observedInterval: TimeSpan.FromSeconds(30));
        using var stop = new CancellationTokenSource();
        var thread = new Thread(() => monitor.Watch(_ => { }, stop.Token)) { IsBackground = true };
        thread.Start();
        try
        {
            Assert.True(SpinWait.SpinUntil(() => reader.Reads >= 1, TimeSpan.FromSeconds(10)));
            signal.Observing = false;
            signal.Trigger(); // the wait in progress was the slow one; this ends it

            Assert.True(
                SpinWait.SpinUntil(() => reader.Reads >= 10, TimeSpan.FromSeconds(10)),
                "the loop stayed on the slow poll after the signal stopped vouching for itself");
        }
        finally
        {
            stop.Cancel();
            thread.Join(TimeSpan.FromSeconds(30));
        }
    }

    [Fact]
    public void ASignalThatDoesNotVouchKeepsTheFastPoll()
    {
        var reader = new CountingReader();
        var monitor = new CameraMicMonitor(
            reader, TimeSpan.FromMilliseconds(20), () => new FakeSignal(), observedInterval: TimeSpan.FromSeconds(30));

        RunFor(monitor, TimeSpan.FromMilliseconds(600));

        Assert.True(reader.Reads >= 5, $"only {reader.Reads} read(s) in 600 ms");
    }

    private static void RunFor(CameraMicMonitor monitor, TimeSpan duration)
    {
        using var stop = new CancellationTokenSource();
        var thread = new Thread(() => monitor.Watch(_ => { }, stop.Token)) { IsBackground = true };
        thread.Start();
        Thread.Sleep(duration);
        stop.Cancel();
        Assert.True(thread.Join(TimeSpan.FromSeconds(30)), "the watch did not stop on cancellation");
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
            activated.Wait(TimeSpan.FromSeconds(30));
        }
        finally
        {
            stop.Cancel();
            thread.Join(TimeSpan.FromSeconds(30));
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
        private volatile bool _observing;
        public bool Disposed { get; private set; }
        public bool Observing { get => _observing; set => _observing = value; }
        public bool IsObserving => _observing;
        public WaitHandle? Start() => _event;
        public void Trigger() => _event.Set();
        public void Dispose() { Disposed = true; _event.Dispose(); }
    }

    private sealed class CountingReader : ICapabilityAccessReader
    {
        private int _reads;

        public int Reads => Volatile.Read(ref _reads);

        public AcquisitionSnapshot<DeviceUsage> ReadWithCoverage() => ReadWithProvenance().ToCoverage();

        public CapabilityAccessSnapshot ReadWithProvenance()
        {
            Interlocked.Increment(ref _reads);
            return new CapabilityAccessSnapshot([], []);
        }
    }
}
