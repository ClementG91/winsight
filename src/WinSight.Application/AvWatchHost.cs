using WinSight.AvMonitor;

namespace WinSight.Application;

/// <summary>
/// Hosts the camera/microphone monitor for as long as the dashboard runs, turning its blocking poll
/// loop into a start/stop lifecycle with an event, the way <see cref="GuardianHost"/> does for
/// persistence.
/// </summary>
/// <remarks>
/// The detection engine for this shipped long ago and nothing ever hosted it: <c>CameraMicMonitor</c>
/// describes itself as an OverSight-class real-time monitor, but its only caller was a CLI watch
/// command that prints to a console. Someone using the app was therefore never told their webcam had
/// turned on — the entire point of that class. This adds the missing lifecycle, not new detection
/// logic.
///
/// Read-only, so unlike ransomware protection it needs no opt-in and writes nothing: it polls the
/// CapabilityAccessManager records Windows already keeps. Failures are swallowed deliberately —
/// a monitor that cannot read must not take the dashboard down with it — but only the ones that
/// mean "Windows would not let us look", so a genuine bug still surfaces.
/// </remarks>
public sealed class AvWatchHost : IDisposable
{
    private readonly CameraMicMonitor _monitor;
    private readonly Lock _gate = new();
    private CancellationTokenSource? _cancellation;
    private Thread? _worker;
    private bool _disposed;

    public AvWatchHost(CameraMicMonitor? monitor = null) => _monitor = monitor ?? new CameraMicMonitor();

    /// <summary>
    /// Raised on the polling thread when an app starts or stops using the webcam or microphone.
    /// </summary>
    public event EventHandler<DeviceEvent>? Detected;

    /// <summary>Begins watching. Safe to call twice; the second call does nothing.</summary>
    public void Start()
    {
        CancellationTokenSource cancellation;
        CancellationToken token;
        lock (_gate)
        {
            if (_disposed || _cancellation is not null)
            {
                return;
            }
            cancellation = new CancellationTokenSource();
            _cancellation = cancellation;
            token = cancellation.Token;
        }

        // The poll loop blocks its thread until cancelled, so it cannot run on the caller's — and it
        // must not run on the thread pool either. A work item that never returns holds a pool thread
        // for the life of the dashboard, and the pool only grows slowly once saturated: on a busy
        // machine this loop can wait seconds for a thread it then never gives back. That starvation
        // is not theoretical — it made the end-to-end test intermittently fail and, on 2026-07-27,
        // failed a release build outright. A loop that runs until shutdown owns a thread of its own.
        var worker = new Thread(() =>
        {
            try
            {
                _monitor.Watch(usage => Detected?.Invoke(this, usage), token);
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown.
            }
            catch (Exception ex) when (!WinSight.NetMonitor.EtwFailure.IsCatastrophic(ex))
            {
                // Windows denied the capability records, a subscriber threw, or the reader failed in
                // a way this host cannot enumerate in advance. Watching stops; everything else in the
                // dashboard, including the on-demand camera/mic scan, is unaffected.
                //
                // The breadth is the point, and it is a consequence of moving this loop off the
                // thread pool. A pool work item that throws produces an unobserved task exception the
                // runtime ignores; a dedicated thread that throws terminates the process. Listing
                // three exception types was adequate under the old model and became a way for a
                // camera-watcher fault to take the whole dashboard down with it, losing every other
                // monitor at once. Only genuinely unrecoverable failures are left to propagate.
            }
        })
        {
            // Background, so a dashboard that is closing is never held open by a poll waiting out
            // its interval.
            IsBackground = true,
            Name = "winsight-av-watch",
        };
        lock (_gate)
        {
            if (_disposed)
            {
                if (ReferenceEquals(_cancellation, cancellation))
                {
                    _cancellation = null;
                }
                cancellation.Dispose();
                return;
            }
            _worker = worker;
            worker.Start();
        }
    }

    /// <summary>How long <see cref="Dispose"/> waits for the poll to unwind before giving up.</summary>
    private static readonly TimeSpan StopTimeout = TimeSpan.FromSeconds(2);

    public void Dispose()
    {
        CancellationTokenSource? cancellation;
        Thread? worker;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            cancellation = _cancellation;
            worker = _worker;
            _worker = null;
        }

        if (cancellation is null)
        {
            return;
        }

        try
        {
            cancellation.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // The worker completed between the state snapshot and cancellation.
        }

        // Wait before disposing the source. The poll loop is blocked on this token's wait handle,
        // and disposing it out from under that thread turns a clean shutdown into an
        // ObjectDisposedException on a background thread nobody is watching. AttributionHost in the
        // sibling project already does exactly this, with a comment describing this bug; this host
        // did the opposite.
        _ = worker?.Join(StopTimeout);
    }
}
