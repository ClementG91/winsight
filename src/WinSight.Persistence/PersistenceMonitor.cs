namespace WinSight.Persistence;

/// <summary>Raised when a genuinely new persistence entry has been surfaced.</summary>
public sealed class PersistenceDetectedEventArgs(PersistenceEvent detected) : EventArgs
{
    public PersistenceEvent Detected { get; } = detected;
}

/// <summary>
/// Wires a real-time <see cref="IPersistenceChangeSource"/> to the pure
/// <see cref="PersistenceMonitorCore"/>: on a change signal it debounces a burst, re-scans, and
/// reconciles. This is the thin I/O layer — its debounce/threading is validated on a real machine,
/// while all the decisions live in the tested core.
/// </summary>
/// <remarks>
/// The re-scan is <b>scoped</b>: a change carries the watch target that fired, and only the
/// enumerators that own that target are re-scanned. This turns a full 22-surface sweep (which also
/// re-verifies signatures) into a small, near-instant scan of the one surface that changed. If the
/// fired target is unknown (an empty target list), it falls back to a full re-scan.
/// </remarks>
public sealed class PersistenceMonitor : IDisposable
{
    private readonly IReadOnlyList<IAutostartEnumerator> _enumerators;
    private readonly IPersistenceChangeSource _source;
    private readonly Func<IReadOnlyList<IAutostartEnumerator>, CancellationToken, IReadOnlyList<AutostartEntry>> _scan;
    private readonly PersistenceMonitorCore _core;
    private readonly IPersistenceBaselineStore? _baselineStore;
    private readonly Func<DateTimeOffset> _clock;
    private readonly TimeSpan _debounce;
    private readonly Lock _gate = new();
    private readonly HashSet<PersistenceWatchTarget> _pendingTargets = [];
    private Timer? _debounceTimer;
    private bool _pendingFullRescan;
    private bool _started;
    private bool _disposed;

    /// <summary>Raised once per genuinely new entry, after debounce and reconciliation.</summary>
    public event EventHandler<PersistenceDetectedEventArgs>? Detected;

    /// <param name="enumerators">The full surface set; the seed scans all of them, a change scans the affected subset.</param>
    /// <param name="source">The real-time change source (registry, filesystem, composite).</param>
    /// <param name="scan">Scans exactly the given enumerator subset and returns resolved, verdict-checked entries.</param>
    public PersistenceMonitor(
        IReadOnlyList<IAutostartEnumerator> enumerators,
        IPersistenceChangeSource source,
        Func<IReadOnlyList<IAutostartEnumerator>, CancellationToken, IReadOnlyList<AutostartEntry>> scan,
        PersistenceMonitorCore? core = null,
        TimeSpan? debounce = null,
        Func<DateTimeOffset>? clock = null,
        IPersistenceBaselineStore? baselineStore = null)
    {
        _enumerators = enumerators ?? throw new ArgumentNullException(nameof(enumerators));
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

        var scan = _scan(_enumerators, cancellationToken);
        var persisted = _baselineStore?.Load();
        if (persisted is not null)
        {
            // Persistence that appeared while WinSight was not running surfaces now, once.
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

    /// <summary>
    /// The enumerators to re-scan for a set of fired targets: those whose <c>WatchTargets</c> include
    /// a fired target. An empty target set (unknown origin), or no match, means re-scan everything.
    /// </summary>
    internal static IReadOnlyList<IAutostartEnumerator> EnumeratorsForTargets(
        IReadOnlyList<IAutostartEnumerator> all,
        IReadOnlyCollection<PersistenceWatchTarget> targets)
    {
        if (targets.Count == 0)
        {
            return all;
        }
        var matched = all.Where(e => e.WatchTargets.Any(targets.Contains)).ToArray();
        return matched.Length > 0 ? matched : all;
    }

    private void OnSurfaceChanged(object? sender, PersistenceSurfaceChangedEventArgs e)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            if (e.ChangedTargets.Count == 0)
            {
                _pendingFullRescan = true;
            }
            else
            {
                foreach (var target in e.ChangedTargets)
                {
                    _pendingTargets.Add(target);
                }
            }
            // Coalesce a burst: (re)arm a one-shot timer so many signals collapse into one re-scan.
            _debounceTimer?.Dispose();
            _debounceTimer = new Timer(_ => RunReconcile(), null, _debounce, Timeout.InfiniteTimeSpan);
        }
    }

    private void RunReconcile()
    {
        IReadOnlyList<IAutostartEnumerator> subset;
        lock (_gate)
        {
            subset = _pendingFullRescan
                ? _enumerators
                : EnumeratorsForTargets(_enumerators, _pendingTargets);
            _pendingTargets.Clear();
            _pendingFullRescan = false;
        }

        IReadOnlyList<PersistenceEvent> detected;
        try
        {
            detected = _core.Reconcile(_scan(subset, CancellationToken.None), _clock());
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
