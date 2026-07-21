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
    private bool _disposed;

    public AvWatchHost(CameraMicMonitor? monitor = null) => _monitor = monitor ?? new CameraMicMonitor();

    /// <summary>
    /// Raised on the polling thread when an app starts or stops using the webcam or microphone.
    /// </summary>
    public event EventHandler<DeviceEvent>? Detected;

    /// <summary>Begins watching. Safe to call twice; the second call does nothing.</summary>
    public void Start()
    {
        CancellationToken token;
        lock (_gate)
        {
            if (_disposed || _cancellation is not null)
            {
                return;
            }
            _cancellation = new CancellationTokenSource();
            token = _cancellation.Token;
        }

        // The poll loop blocks its thread until cancelled, so it cannot run on the caller's.
        Task.Run(
            () =>
            {
                try
                {
                    _monitor.Watch(usage => Detected?.Invoke(this, usage), token);
                }
                catch (OperationCanceledException)
                {
                    // Normal shutdown.
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException
                                             or System.Security.SecurityException
                                             or IOException)
                {
                    // Windows denied the capability records. Watching stops; everything else in the
                    // dashboard, including the on-demand camera/mic scan, is unaffected.
                }
            },
            CancellationToken.None);
    }

    public void Dispose()
    {
        CancellationTokenSource? cancellation;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            cancellation = _cancellation;
            _cancellation = null;
        }

        if (cancellation is not null)
        {
            cancellation.Cancel();
            cancellation.Dispose();
        }
    }
}
