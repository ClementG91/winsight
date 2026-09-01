using WinSight.Application;
using WinSight.AvMonitor;
using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// The camera/mic host's shutdown, which used to dispose a cancellation source out from under the
/// thread blocked on its wait handle.
/// </summary>
/// <remarks>
/// <b>The twin that was already correct.</b> <c>AttributionHost</c> in the sibling project does
/// Cancel, then Join, and lets the worker own its own source - with a comment describing precisely
/// this bug. This host did the opposite: <c>Cancel()</c> immediately followed by <c>Dispose()</c>,
/// while the poll loop sits in <c>token.WaitHandle.WaitOne(interval)</c>. Disposing the source there
/// turns an ordinary shutdown into an <c>ObjectDisposedException</c> on a background thread nobody
/// observes.
///
/// That pattern - a defect fixed in one place and left standing in its neighbour - is the most
/// repeated finding in the audit these tests belong to, which is why the assertions are about the
/// shape of the lifecycle rather than about one exception type.
/// </remarks>
public sealed class HostLifecycleTwinTests
{
    [Fact]
    public void DisposeWaitsForThePollLoopInsteadOfPullingItsTokenAway()
    {
        var reader = new SignallingReader();
        using var host = new AvWatchHost(new CameraMicMonitor(reader, TimeSpan.FromMilliseconds(25)));

        host.Start();
        Assert.True(reader.Polled.Wait(TimeSpan.FromSeconds(5)), "the poll loop never started");

        host.Dispose();

        // The loop is not running any more, and nothing it did threw. A source disposed from under
        // WaitHandle.WaitOne would have surfaced here.
        Assert.Null(reader.Failure);
        var pollsAtDispose = reader.PollCount;
        Thread.Sleep(200);
        Assert.Equal(pollsAtDispose, reader.PollCount);
    }

    [Fact]
    public void DisposeIsIdempotent()
    {
        var host = new AvWatchHost(new CameraMicMonitor(new SignallingReader()));

        host.Start();
        host.Dispose();
        host.Dispose();
    }

    [Fact]
    public void DisposeWithoutStartIsSafe() =>
        new AvWatchHost(new CameraMicMonitor(new SignallingReader())).Dispose();

    [Fact]
    public void StartAfterDisposeDoesNothing()
    {
        var reader = new SignallingReader();
        var host = new AvWatchHost(new CameraMicMonitor(reader, TimeSpan.FromMilliseconds(25)));

        host.Dispose();
        host.Start();

        Assert.False(reader.Polled.Wait(TimeSpan.FromMilliseconds(300)));
    }

    /// <summary>Records that the poll loop ran, and anything it threw.</summary>
    private sealed class SignallingReader : ICapabilityAccessReader
    {
        private int _polls;

        internal ManualResetEventSlim Polled { get; } = new(false);

        internal int PollCount => Volatile.Read(ref _polls);

        internal Exception? Failure { get; private set; }

        public IReadOnlyList<DeviceUsage> Read()
        {
            try
            {
                Interlocked.Increment(ref _polls);
                Polled.Set();
                return [];
            }
            catch (Exception ex)
            {
                Failure = ex;
                throw;
            }
        }
    }
}
