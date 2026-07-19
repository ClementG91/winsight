namespace WinSight.Persistence;

/// <summary>Raised when a genuinely new persistence entry has been surfaced.</summary>
public sealed class PersistenceDetectedEventArgs(PersistenceEvent detected) : EventArgs
{
    public PersistenceEvent Detected { get; } = detected;
}

/// <summary>
/// Wires a real-time <see cref="IPersistenceChangeSource"/> to the pure
/// <see cref="PersistenceMonitorCore"/>: on a change signal it debounces a burst, re-runs the scan,
/// and reconciles. This is the thin I/O layer — its debounce/threading is validated on a real
/// machine, while all the decisions live in the tested core.
/// </summary>
public sealed class PersistenceMonitor : IDisposable
{
    private readonly IPersistenceChangeSource _source;
    private readonly Func<CancellationToken, IReadOnlyList<AutostartEntry>> _scan;
    private readonly PersistenceMonitorCore _core;
    private readonly IPersistenceBaselineStore? _baselineStore;
    private readonly Func<DateTimeOffset> _clock;
    private readonly TimeSpan _debounce;
    private readonly Lock _gate = new();
    private Timer? _debounceTimer;
    private bool _started;
    private bool _disposed;

    /// <summary>Raised once per genuinely new entry, after debounce and reconciliation.</summary>
    public event EventHandler<PersistenceDetectedEventArgs>? Detected;

    public PersistenceMonitor(
        IPersistenceChangeSource source,
        Func<CancellationToken, IReadOnlyList<AutostartEntry>> scan,
        PersistenceMonitorCore? core = null,
        TimeSpan? debounce = null,
        Func<DateTimeOffset>? clock = null,
        IPersistenceBaselineStore? baselineStore = null)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _scan = scan ?? throw new ArgumentNullException(nameof(scan));
        _core = core ?? new PersistenceMonitorCore();
        _debounce = debounce ?? TimeSpan.FromMilliseconds(750);
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _baselineStore = baselineStore;
    }

    /// <summary>The pure core; exposes the change log for the presenter/UI.</summary>
    public PersistenceMonitorCore Core => _core;

    /// <summary>Seeds the baseline from an initial full scan, then starts listening. Idempotent.</summary>
    public void Start(CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (_started || _disposed)
            {
                return;
            }
            _started = true;
        }
        var scan = _scan(cancellationToken);
        var persisted = _baselineStore?.Load();
        if (persisted is not null)
        {
            // Persistence that appeared while WinSight was not running surfaces now, once, then the
            // baseline becomes the current state.
            foreach (var detection in _core.ReconcileFromPersistedBaseline(persisted, scan, _clock()))
            {
                Detected?.Invoke(this, new PersistenceDetectedEventArgs(detection));
            }
        }
        else
        {
            _core.SeedBaseline(scan);
        }
        _baselineStore?.Save(_core.CurrentBaseline);

        _source.SurfaceChanged += OnSurfaceChanged;
        _source.Start();
    }

    private void OnSurfaceChanged(object? sender, PersistenceSurfaceChangedEventArgs e)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            // Coalesce a burst: (re)arm a one-shot timer so many signals collapse into one re-scan.
            _debounceTimer?.Dispose();
            _debounceTimer = new Timer(_ => RunReconcile(), null, _debounce, Timeout.InfiniteTimeSpan);
        }
    }

    private void RunReconcile()
    {
        IReadOnlyList<PersistenceEvent> detected;
        try
        {
            detected = _core.Reconcile(_scan(CancellationToken.None), _clock());
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or IOException
                                     or System.Security.SecurityException)
        {
            // A transient scan failure is not fatal; the next change signal retries.
            return;
        }

        foreach (var ev in detected)
        {
            Detected?.Invoke(this, new PersistenceDetectedEventArgs(ev));
        }

        if (detected.Count > 0)
        {
            // Persist the advanced baseline so a crash does not re-alert on entries already surfaced.
            _baselineStore?.Save(_core.CurrentBaseline);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
        }
        _source.SurfaceChanged -= OnSurfaceChanged;
        _debounceTimer?.Dispose();
        _source.Dispose();

        // Save the final known baseline for next launch — but only if it was actually seeded, so an
        // early/failed start never overwrites a good baseline with an empty one.
        if (_core.IsSeeded)
        {
            _baselineStore?.Save(_core.CurrentBaseline);
        }
    }
}
