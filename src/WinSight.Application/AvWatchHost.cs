using WinSight.AvMonitor;

namespace WinSight.Application;

/// <summary>An immutable view of the worker and its latest acquisition coverage.</summary>
public sealed record AvWatchStatus(
    bool IsRunning, bool HasSnapshot, int UnreadableSources, int UnreadableItems, Exception? Failure)
{
    /// <summary>Events a subscriber failed to handle. The watch continued; the alert may be missing.</summary>
    public int NotificationFailures { get; init; }

    /// <summary>The last subscriber exception, kept whole for diagnosis.</summary>
    public Exception? LastNotificationFailure { get; init; }

    /// <summary>Automatic restarts performed after an unexpected worker failure.</summary>
    public int Restarts { get; init; }

    /// <summary>True when the bounded automatic restarts are spent and the worker is stopped.</summary>
    public bool RestartsExhausted { get; init; }
}

/// <summary>Owns the camera/microphone polling thread and reports its actual health.</summary>
/// <remarks>
/// <para><b>A subscriber cannot blind the watch.</b> Each handler runs in its own containment: a handler
/// that throws is counted and recorded, other handlers still receive the event, and polling continues.
/// Before, one faulty consumer stopped camera/microphone monitoring for the rest of the session.</para>
/// <para><b>Controlled recovery.</b> An unexpected acquisition failure stops the worker and is reported as
/// failed; the host restarts it after 5 s, 30 s and 120 s, then stops trying until <see cref="Start"/> is
/// called again. A catastrophic failure is never contained.</para>
/// </remarks>
public sealed class AvWatchHost : IDisposable
{
    private readonly CameraMicMonitor _monitor;
    private readonly IReadOnlyList<TimeSpan> _restartDelays;
    private readonly Lock _gate = new();
    private CancellationTokenSource? _cancellation;
    private Thread? _worker;
    private Timer? _restartTimer;
    private int _restartAttempt;
    private bool _disposed;
    private AvWatchStatus _status = new(false, false, 0, 0, null);

    public AvWatchHost(CameraMicMonitor? monitor = null)
        : this(monitor, null)
    {
    }

    internal AvWatchHost(CameraMicMonitor? monitor, IReadOnlyList<TimeSpan>? restartDelays)
    {
        // Production camera/mic watch is event-driven: a fresh consent-store change signal per Watch run
        // wakes the loop the moment a device is turned on, with the 1 s poll kept as the fallback.
        _monitor = monitor ?? new CameraMicMonitor(changeSignalFactory: () => new ConsentStoreChangeSignal());
        _restartDelays = restartDelays ?? [TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(120)];
    }

    /// <summary>Raised on the polling thread for a device activation/deactivation.</summary>
    public event EventHandler<DeviceEvent>? Detected;

    public AvWatchStatus Status => Volatile.Read(ref _status);

    /// <summary>Four acquisition surfaces: webcam and microphone, in HKCU and HKLM.</summary>
    public MonitorHealth Health(bool enabled)
    {
        var status = Status;
        return MonitorHealth.For("Camera/Mic", enabled,
            armed: status.IsRunning && status.HasSnapshot && status.Failure is null
                ? Math.Clamp(4 - status.UnreadableSources, 0, 4) : 0,
            requested: 4,
            lostObservations: status.UnreadableItems > 0 || status.NotificationFailures > 0);
    }

    /// <summary>Starts the worker if it is not running; also resets the automatic restart budget.</summary>
    public void Start()
    {
        lock (_gate)
        {
            _restartAttempt = 0;
            _restartTimer?.Dispose();
            _restartTimer = null;
            StartLocked(isRestart: false);
        }
    }

    private void StartLocked(bool isRestart)
    {
        if (_disposed || _worker is not null)
        {
            return;
        }
        var cancellation = new CancellationTokenSource();
        _cancellation = cancellation;
        var previous = Status;
        Volatile.Write(ref _status, new AvWatchStatus(true, false, 0, 0, null)
        {
            NotificationFailures = previous.NotificationFailures,
            LastNotificationFailure = previous.LastNotificationFailure,
            Restarts = previous.Restarts + (isRestart ? 1 : 0),
        });
        var worker = new Thread(() => Run(cancellation))
        {
            IsBackground = true,
            Name = "winsight-av-watch",
        };
        _worker = worker;
        try
        {
            worker.Start();
        }
        catch
        {
            _worker = null;
            _cancellation = null;
            Volatile.Write(ref _status, Status with { IsRunning = false });
            cancellation.Dispose();
            throw;
        }
    }

    private void Run(CancellationTokenSource cancellation)
    {
        var token = cancellation.Token;
        var failed = false;
        try
        {
            _monitor.Watch(Publish, token, snapshot =>
            {
                Volatile.Write(ref _status, Status with
                {
                    IsRunning = true,
                    HasSnapshot = true,
                    UnreadableSources = snapshot.UnreadableSources,
                    UnreadableItems = snapshot.UnreadableItems,
                    Failure = null,
                    RestartsExhausted = false,
                });
                lock (_gate)
                {
                    _restartAttempt = 0; // a working acquisition restores the full restart budget
                }
            });
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            // Normal shutdown.
        }
        catch (Exception ex) when (!WinSight.NetMonitor.EtwFailure.IsCatastrophic(ex))
        {
            // A dedicated thread must contain ordinary faults, while preserving a visible failure.
            Volatile.Write(ref _status, Status with { IsRunning = false, Failure = ex });
            failed = true;
        }
        finally
        {
            lock (_gate)
            {
                Volatile.Write(ref _status, Status with { IsRunning = false });
                _worker = null;
                _cancellation = null;
                // Only the worker disposes its source, after its last wait on the token handle.
                cancellation.Dispose();
                if (failed)
                {
                    ScheduleRestartLocked();
                }
            }
        }
    }

    private void Publish(DeviceEvent deviceEvent)
    {
        foreach (var handler in Detected?.GetInvocationList() ?? [])
        {
            try
            {
                ((EventHandler<DeviceEvent>)handler)(this, deviceEvent);
            }
            catch (Exception ex) when (!WinSight.NetMonitor.EtwFailure.IsCatastrophic(ex))
            {
                Volatile.Write(ref _status, Status with
                {
                    NotificationFailures = Status.NotificationFailures + 1,
                    LastNotificationFailure = ex,
                });
            }
        }
    }

    private void ScheduleRestartLocked()
    {
        if (_disposed)
        {
            return;
        }
        if (_restartAttempt >= _restartDelays.Count)
        {
            Volatile.Write(ref _status, Status with { RestartsExhausted = true });
            return;
        }
        var delay = _restartDelays[_restartAttempt++];
        _restartTimer?.Dispose();
        _restartTimer = new Timer(_ =>
        {
            lock (_gate)
            {
                _restartTimer?.Dispose();
                _restartTimer = null;
                try
                {
                    StartLocked(isRestart: true);
                }
                catch (Exception ex) when (!WinSight.NetMonitor.EtwFailure.IsCatastrophic(ex))
                {
                    // Could not create the thread: keep the failure visible and try the next delay.
                    Volatile.Write(ref _status, Status with { IsRunning = false, Failure = ex });
                    ScheduleRestartLocked();
                }
            }
        }, null, delay, Timeout.InfiniteTimeSpan);
    }

    public void Dispose()
    {
        Thread? worker;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            worker = _worker;
            _cancellation?.Cancel();
            _restartTimer?.Dispose();
            _restartTimer = null;
        }
        // A subscriber can dispose its own host. Never try to join the current thread.
        if (worker is not null && worker != Thread.CurrentThread)
        {
            _ = worker.Join(TimeSpan.FromSeconds(2));
        }
    }
}
