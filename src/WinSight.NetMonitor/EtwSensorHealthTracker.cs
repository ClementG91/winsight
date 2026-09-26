using Microsoft.Diagnostics.Tracing.Session;

using WinSight.Core;

namespace WinSight.NetMonitor;

/// <summary>
/// Shared health accounting for TraceEvent-backed sensors. Reading <see cref="TraceEventSession.EventsLost"/>
/// is the supported real-time loss signal; ignoring it turns an overloaded session into a quiet one.
/// </summary>
internal sealed class EtwSensorHealthTracker(string name) : ISensorHealthSource
{
    private readonly string _name = name;
    private readonly Lock _gate = new();
    private Func<long>? _lostProvider;
    private SensorLifecycle _lifecycle = SensorLifecycle.NotStarted;
    private string? _failureCode;
    private long _observed;
    private long _nativeLost;
    private long _applicationLost;
    private long _deliveryFailures;

    public SensorHealthSnapshot SensorHealth
    {
        get
        {
            RefreshLostEvents();
            lock (_gate)
            {
                return new SensorHealthSnapshot(
                    _name,
                    _lifecycle,
                    RequestedSources: 1,
                    ActiveSources: _lifecycle == SensorLifecycle.Running ? 1 : 0,
                    ObservedEvents: Interlocked.Read(ref _observed),
                    LostEvents: SaturatingAdd(
                        Interlocked.Read(ref _nativeLost),
                        Interlocked.Read(ref _applicationLost)),
                    RecoveryAttempts: 0,
                    SuccessfulRecoveries: 0,
                    DeliveryFailures: Interlocked.Read(ref _deliveryFailures),
                    FailureCode: _failureCode);
            }
        }
    }

    public void Running(TraceEventSession session)
    {
        ArgumentNullException.ThrowIfNull(session);
        Running(() => session.EventsLost);
    }

    internal void Running(Func<long> lostProvider)
    {
        ArgumentNullException.ThrowIfNull(lostProvider);
        lock (_gate)
        {
            _lostProvider = lostProvider;
            _lifecycle = SensorLifecycle.Running;
            _failureCode = null;
        }
    }

    public void Observed()
    {
        IncrementSaturating(ref _observed);
    }

    /// <summary>
    /// Records events accepted by ETW but rejected by a bounded application delivery queue. Native
    /// and application loss are combined in the provider-neutral snapshot because either makes the
    /// operator's observation incomplete.
    /// </summary>
    public void ApplicationEventsLost(long count = 1)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(count);
        AddSaturating(ref _applicationLost, count);
    }

    public void DeliveryFailed() => IncrementSaturating(ref _deliveryFailures);

    public void Stopped()
    {
        RefreshLostEvents();
        lock (_gate)
        {
            _lostProvider = null;
            _lifecycle = SensorLifecycle.Stopped;
            _failureCode = null;
        }
    }

    public void Failed(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        RefreshLostEvents();
        lock (_gate)
        {
            _lostProvider = null;
            _lifecycle = SensorLifecycle.Failed;
            _failureCode = EtwFailure.Token(EtwFailure.Classify(exception));
        }
    }

    public void FailedUnexpectedReturn()
    {
        RefreshLostEvents();
        lock (_gate)
        {
            _lostProvider = null;
            _lifecycle = SensorLifecycle.Failed;
            _failureCode = EtwFailure.Token(EtwFailureCode.Unexpected);
        }
    }

    private void RefreshLostEvents()
    {
        Func<long>? lostProvider;
        lock (_gate)
        {
            lostProvider = _lostProvider;
        }
        if (lostProvider is null)
        {
            return;
        }

        long reported;
        try
        {
            reported = lostProvider();
        }
        catch (Exception ex) when (!EtwFailure.IsCatastrophic(ex))
        {
            // Loss telemetry must not be able to end the sensor it describes. The session boundary
            // still reports a real failure if processing itself stops.
            return;
        }

        long current;
        do
        {
            current = Interlocked.Read(ref _nativeLost);
            if (reported <= current)
            {
                return;
            }
        }
        while (Interlocked.CompareExchange(ref _nativeLost, reported, current) != current);
    }

    private static void IncrementSaturating(ref long value) => AddSaturating(ref value, 1);

    private static void AddSaturating(ref long value, long addend)
    {
        long current;
        long updated;
        do
        {
            current = Interlocked.Read(ref value);
            updated = current >= long.MaxValue - addend ? long.MaxValue : current + addend;
            if (updated == current)
            {
                return;
            }
        }
        while (Interlocked.CompareExchange(ref value, updated, current) != current);
    }

    private static long SaturatingAdd(long left, long right) =>
        left >= long.MaxValue - right ? long.MaxValue : left + right;
}
