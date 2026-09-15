namespace WinSight.Persistence;

/// <summary>Raised when a genuinely new persistence entry has been surfaced.</summary>
public sealed class PersistenceDetectedEventArgs(PersistenceEvent detected) : EventArgs
{
    public PersistenceEvent Detected { get; } = detected;
}

/// <summary>The monitor operation that failed.</summary>
public enum PersistenceMonitorOperation
{
    Scan,
    Notification,
    BaselineSave,
    SourceShutdown,
}

/// <summary>One contained failure, kept whole so it can be diagnosed.</summary>
public sealed record PersistenceMonitorFault(
    PersistenceMonitorOperation Operation,
    Exception Exception,
    DateTimeOffset AtUtc);

/// <summary>
/// What the monitor could not do. Nothing here is silent: a failed scan, save or notification is
/// counted, the last one is kept whole, and undelivered arrivals stay visible until delivered.
/// </summary>
public sealed record PersistenceMonitorDiagnostics(
    int PendingNotifications,
    int ScanFailures,
    int NotificationFailures,
    int SaveFailures,
    bool RetryScheduled,
    bool AutomaticRetriesExhausted,
    bool ShutdownDeferred,
    PersistenceMonitorFault? LastFault)
{
    /// <summary>True when an arrival is undelivered or the last scan or save has not recovered.</summary>
    public bool IsDegraded { get; init; }

    /// <summary>
    /// Arrivals reported but not kept in the bounded display list because it was full. They were
    /// notified; only the in-app list is incomplete.
    /// </summary>
    public int UnlistedArrivals { get; init; }
}

/// <summary>
/// Wires a real-time <see cref="IPersistenceChangeSource"/> to the pure
/// <see cref="PersistenceMonitorCore"/>: on a change signal it debounces a burst, re-scans, and
/// reconciles. This is the thin I/O layer — its debounce/threading is validated on a real machine,
/// while all the decisions live in the tested core.
/// </summary>
/// <remarks>
/// <para>The re-scan is <b>scoped</b>: a change carries the watch target that fired, and only the
/// enumerators that own that target are re-scanned. If the fired target is unknown (an empty target
/// list), it falls back to a full re-scan.</para>
/// <para><b>Failure boundary.</b> Scans, baseline saves and notifications run on timer threads, where an
/// unhandled exception ends the process and every other protection with it. Recoverable failures
/// are contained, recorded in <see cref="Diagnostics"/> and retried on a bounded schedule; failures
/// that leave the process unable to continue safely (<see cref="IsCatastrophic"/>) still propagate.
/// An arrival is never written to the saved baseline before every subscriber has received it, so an
/// arrival that stays undelivered is reported again on the next launch.</para>
/// <para><b>Shutdown.</b> <see cref="Dispose"/> cancels acquisition and waits a bounded time for the
/// scan in progress. Registry, COM and WinTrust reads do not all observe cancellation, so when the scan
/// does not leave in time the remaining shutdown work (source disposal, final save) is completed by
/// that scan's thread as it exits, instead of blocking the caller — typically the UI thread.</para>
/// </remarks>
public sealed class PersistenceMonitor : IDisposable
{
    /// <summary>Delivery attempts per arrival before automatic retries stop for this session.</summary>
    internal const int MaxDeliveryAttempts = 4;

    private static readonly TimeSpan[] DefaultRetryDelays =
        [TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(60)];

    private readonly IReadOnlyList<IAutostartEnumerator> _enumerators;
    private readonly IPersistenceChangeSource _source;
    private readonly Func<IReadOnlyList<IAutostartEnumerator>, CancellationToken, PersistenceScanResult> _scan;
    private readonly PersistenceMonitorCore _core;
    private readonly IPersistenceBaselineStore? _baselineStore;
    private readonly Func<DateTimeOffset> _clock;
    private readonly TimeSpan _debounce;
    private readonly TimeSpan _disposeWait;
    private readonly IReadOnlyList<TimeSpan> _retryDelays;
    private readonly Lock _gate = new();
    private readonly Lock _scanGate = new();
    private readonly Lock _saveGate = new();
    private readonly Lock _publishGate = new();
    private readonly CancellationTokenSource _lifetime = new();
    // Arrivals reconciled into the in-memory baseline whose delivery has not completed, in order.
    private readonly List<PendingNotification> _undelivered = [];
    private readonly HashSet<PersistenceWatchTarget> _pendingTargets = [];
    private Timer? _debounceTimer;
    private Timer? _retryTimer;
    private int _retryAttempt;
    private bool _retriesExhausted;
    private bool _pendingFullRescan;
    private bool _saveRetryNeeded;
    private bool _scanRetryNeeded;
    private int _scanFailures;
    private int _notificationFailures;
    private int _saveFailures;
    private PersistenceMonitorFault? _lastFault;
    private bool _started;
    private bool _disposed;
    private bool _cleanupDone;

    /// <summary>Raised once per genuinely new entry, after debounce and reconciliation.</summary>
    /// <remarks>
    /// Raised on a background thread and never under a lock <see cref="Dispose"/> waits on. A handler
    /// that throws does not stop the monitor: the arrival stays pending for that handler and is retried.
    /// </remarks>
    public event EventHandler<PersistenceDetectedEventArgs>? Detected;

    /// <param name="enumerators">The full surface set; the seed scans all of them, a change scans the affected subset.</param>
    /// <param name="source">The real-time change source (registry, filesystem, composite).</param>
    /// <param name="scan">Scans exactly the given enumerator subset and returns resolved, verdict-checked entries.</param>
    public PersistenceMonitor(
        IReadOnlyList<IAutostartEnumerator> enumerators,
        IPersistenceChangeSource source,
        Func<IReadOnlyList<IAutostartEnumerator>, CancellationToken, PersistenceScanResult> scan,
        PersistenceMonitorCore? core = null,
        TimeSpan? debounce = null,
        Func<DateTimeOffset>? clock = null,
        IPersistenceBaselineStore? baselineStore = null)
        : this(enumerators, source, scan, core, debounce, clock, baselineStore, null, null)
    {
    }

    internal PersistenceMonitor(
        IReadOnlyList<IAutostartEnumerator> enumerators,
        IPersistenceChangeSource source,
        Func<IReadOnlyList<IAutostartEnumerator>, CancellationToken, PersistenceScanResult> scan,
        PersistenceMonitorCore? core,
        TimeSpan? debounce,
        Func<DateTimeOffset>? clock,
        IPersistenceBaselineStore? baselineStore,
        TimeSpan? disposeWait,
        IReadOnlyList<TimeSpan>? retryDelays)
    {
        _enumerators = enumerators ?? throw new ArgumentNullException(nameof(enumerators));
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _scan = scan ?? throw new ArgumentNullException(nameof(scan));
        _core = core ?? new PersistenceMonitorCore();
        _debounce = debounce ?? TimeSpan.FromMilliseconds(750);
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _baselineStore = baselineStore;
        // Long enough for a cooperative scan (cancellation is checked between surfaces and files) to
        // leave and let the final save run synchronously; short enough not to stall a closing window.
        _disposeWait = disposeWait ?? TimeSpan.FromMilliseconds(300);
        _retryDelays = retryDelays ?? DefaultRetryDelays;
    }

    /// <summary>The pure core; exposes the change log for the presenter/UI.</summary>
    public PersistenceMonitorCore Core => _core;

    /// <summary>
    /// What real-time monitoring was asked to watch, and what it actually armed.
    /// </summary>
    public (int Requested, int Armed) WatchCoverage =>
        _source is IPersistenceWatchCoverage coverage
            ? (coverage.RequestedLocations, coverage.ArmedLocations)
            : (0, 0);

    /// <summary>True once <see cref="Start"/> has completed its seed and attached the source.</summary>
    public bool IsStarted
    {
        get { lock (_gate) { return _started && !_disposed; } }
    }

    /// <summary>Contained failures and pending deliveries, for the health display.</summary>
    public PersistenceMonitorDiagnostics Diagnostics
    {
        get
        {
            lock (_gate)
            {
                return new PersistenceMonitorDiagnostics(
                    _undelivered.Count,
                    _scanFailures,
                    _notificationFailures,
                    _saveFailures,
                    _retryTimer is not null,
                    _retriesExhausted,
                    _disposed && !_cleanupDone,
                    _lastFault)
                {
                    IsDegraded = _undelivered.Count > 0 || _scanRetryNeeded || _saveRetryNeeded,
                    UnlistedArrivals = _core.Log.DroppedChanges,
                };
            }
        }
    }

    /// <summary>
    /// Failures that must not be contained: the process state can no longer be trusted.
    /// </summary>
    internal static bool IsCatastrophic(Exception exception) =>
        exception is OutOfMemoryException
            or StackOverflowException
            or AccessViolationException
            or InsufficientExecutionStackException;

    /// <summary>Seeds the baseline from an initial full scan, then starts listening. Idempotent.</summary>
    /// <remarks>
    /// A failed initial scan or watcher arming still throws to the caller, which decides how to
    /// present a monitor that never started. Failed notifications and saves do not throw.
    /// </remarks>
    public void Start(CancellationToken cancellationToken = default)
    {
        try
        {
            lock (_scanGate)
            {
                lock (_gate)
                {
                    if (_started || _disposed)
                    {
                        return;
                    }
                }
                PersistenceScanResult scan;
                try
                {
                    using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                        cancellationToken, _lifetime.Token);
                    scan = _scan(_enumerators, linked.Token);
                }
                catch (Exception ex) when (ex is not OperationCanceledException && !IsCatastrophic(ex))
                {
                    RecordFault(PersistenceMonitorOperation.Scan, ex);
                    throw;
                }
                var persisted = _baselineStore?.Load();
                lock (_gate)
                {
                    if (_disposed)
                    {
                        return;
                    }
                    if (persisted is not null)
                    {
                        EnqueueLocked(_core.ReconcileFromPersistedBaseline(persisted, scan, _clock()));
                    }
                    else
                    {
                        _core.SeedBaseline(scan.Entries);
                    }
                }
                TrySaveBaseline();

                _source.SurfaceChanged += OnSurfaceChanged;
                try
                {
                    _source.Start();
                    lock (_gate)
                    {
                        _started = true;
                    }
                }
                catch
                {
                    _source.SurfaceChanged -= OnSurfaceChanged;
                    throw;
                }
            }
        }
        finally
        {
            // Startup reconciliation happened even if watcher arming failed: report those arrivals
            // now. Anything not delivered is excluded from every saved baseline.
            PublishPending();
            CompleteDisposalIfIdle();
            ScheduleRetryIfNeeded();
        }
    }

    /// <summary>
    /// Clears the automatic retry budget and tries again now: undelivered notifications, and a failed
    /// scan or save. For an operator-initiated retry after the cause has been fixed.
    /// </summary>
    public void RetryNow()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            foreach (var pending in _undelivered)
            {
                pending.Attempts = 0;
            }
            _retryAttempt = 0;
            _retriesExhausted = false;
            _retryTimer?.Dispose();
            _retryTimer = new Timer(_ => OnRetryTimer(), null, TimeSpan.Zero, Timeout.InfiniteTimeSpan);
        }
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

    private void OnRetryTimer()
    {
        lock (_gate)
        {
            _retryTimer?.Dispose();
            _retryTimer = null;
        }
        RunReconcile();
    }

    private void RunReconcile()
    {
        try
        {
            // A slow scan can outlast the debounce interval. Serialize scan + coverage + reconciliation
            // so an older snapshot never overwrites a newer one and enumerator counters cannot race.
            lock (_scanGate)
            {
                bool scanNeeded;
                bool saveNeeded;
                lock (_gate)
                {
                    if (_disposed)
                    {
                        return;
                    }
                    scanNeeded = _pendingFullRescan || _pendingTargets.Count > 0;
                    saveNeeded = _saveRetryNeeded;
                }
                if (scanNeeded)
                {
                    RunScanSerially();
                }
                else if (saveNeeded)
                {
                    TrySaveBaseline();
                }
            }
            PublishPending();
        }
        finally
        {
            CompleteDisposalIfIdle();
            ScheduleRetryIfNeeded();
        }
    }

    private void RunScanSerially()
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

        try
        {
            var scan = _scan(subset, _lifetime.Token);
            lock (_gate)
            {
                if (_disposed)
                {
                    // Shutdown won the race: leave the baseline as it was, so nothing observed by
                    // this scan is acknowledged without being reported.
                    return;
                }
                EnqueueLocked(_core.Reconcile(scan, _clock()));
                _scanRetryNeeded = false;
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex) when (!IsCatastrophic(ex))
        {
            // Includes bugs and unexpected COM/WMI failures, not only access errors: on a timer thread
            // the alternative is the process ending. The work is requeued, never forgotten, so the
            // retry or the next change signal scans the same surfaces again.
            lock (_gate)
            {
                if (ReferenceEquals(subset, _enumerators) || subset.Count == _enumerators.Count)
                {
                    _pendingFullRescan = true;
                }
                else
                {
                    foreach (var target in subset.SelectMany(enumerator => enumerator.WatchTargets))
                    {
                        _pendingTargets.Add(target);
                    }
                    _pendingFullRescan |= subset.All(enumerator => enumerator.WatchTargets.Count == 0);
                }
                _scanRetryNeeded = true;
            }
            RecordFault(PersistenceMonitorOperation.Scan, ex);
            return;
        }

        // Confirmed removals also advance the baseline: persist even without a new alert so a
        // later installation is recognized after a crash or restart.
        TrySaveBaseline();
    }

    private void EnqueueLocked(IReadOnlyList<PersistenceEvent> detected)
    {
        foreach (var ev in detected)
        {
            _undelivered.RemoveAll(pending => pending.Event.Identity == ev.Identity);
            _undelivered.Add(new PendingNotification(ev));
        }
    }

    /// <summary>
    /// Persists the baseline minus arrivals whose delivery has not completed. Delivery is
    /// at-least-once: a crash after delivery can repeat an alert, but a shutdown, subscriber failure
    /// or crash before delivery never turns an arrival into a silently known entry.
    /// </summary>
    private void TrySaveBaseline()
    {
        if (_baselineStore is null)
        {
            return;
        }
        lock (_saveGate)
        {
            IReadOnlyCollection<PersistenceIdentity> snapshot;
            lock (_gate)
            {
                var undelivered = _undelivered.Select(pending => pending.Event.Identity).ToHashSet();
                snapshot = undelivered.Count == 0
                    ? _core.CurrentBaseline
                    : _core.CurrentBaseline.Where(id => !undelivered.Contains(id)).ToArray();
            }
            try
            {
                _baselineStore.Save(snapshot);
                lock (_gate)
                {
                    _saveRetryNeeded = false;
                }
            }
            catch (Exception ex) when (!IsCatastrophic(ex))
            {
                lock (_gate)
                {
                    _saveRetryNeeded = true;
                }
                RecordFault(PersistenceMonitorOperation.BaselineSave, ex);
            }
        }
    }

    private void PublishPending()
    {
        // UI handlers may synchronously dispatch. Never hold a lock Dispose waits for here; this gate
        // only keeps two publishers from delivering the same arrival concurrently.
        var delivered = false;
        lock (_publishGate)
        {
            List<PendingNotification> batch;
            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }
                batch = [.. _undelivered.Where(pending => pending.Attempts < MaxDeliveryAttempts)];
            }
            var handlers = Detected?.GetInvocationList() ?? [];
            foreach (var pending in batch)
            {
                lock (_gate)
                {
                    if (_disposed)
                    {
                        return;
                    }
                    if (!_undelivered.Contains(pending))
                    {
                        continue;
                    }
                    pending.Attempts++;
                }
                var complete = true;
                foreach (var handler in handlers)
                {
                    if (pending.DeliveredTo.Contains(handler))
                    {
                        continue;
                    }
                    try
                    {
                        ((EventHandler<PersistenceDetectedEventArgs>)handler)(
                            this, new PersistenceDetectedEventArgs(pending.Event));
                        pending.DeliveredTo.Add(handler);
                    }
                    catch (Exception ex) when (!IsCatastrophic(ex))
                    {
                        complete = false;
                        RecordFault(PersistenceMonitorOperation.Notification, ex);
                    }
                }
                if (complete)
                {
                    lock (_gate)
                    {
                        _undelivered.Remove(pending);
                    }
                    delivered = true;
                }
            }
        }
        bool disposed;
        lock (_gate)
        {
            disposed = _disposed;
        }
        if (delivered && !disposed)
        {
            // Delivered arrivals may now be acknowledged durably. Saves are serialized and each
            // snapshots the latest state, so this cannot overwrite a newer baseline with an older one.
            TrySaveBaseline();
        }
    }

    private void RecordFault(PersistenceMonitorOperation operation, Exception exception)
    {
        lock (_gate)
        {
            switch (operation)
            {
                case PersistenceMonitorOperation.Scan:
                    _scanFailures++;
                    break;
                case PersistenceMonitorOperation.Notification:
                    _notificationFailures++;
                    break;
                case PersistenceMonitorOperation.BaselineSave:
                    _saveFailures++;
                    break;
            }
            _lastFault = new PersistenceMonitorFault(operation, exception, _clock());
        }
    }

    private void ScheduleRetryIfNeeded()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            var retryable = _undelivered.Any(pending => pending.Attempts < MaxDeliveryAttempts)
                || _scanRetryNeeded
                || _saveRetryNeeded;
            if (!retryable)
            {
                // Recovered, or only arrivals whose delivery budget is spent remain.
                _retriesExhausted = _undelivered.Count > 0;
                _retryAttempt = 0;
                return;
            }
            if (_retryTimer is not null)
            {
                return;
            }
            if (_retryAttempt >= _retryDelays.Count)
            {
                // No infinite loop: the next change signal, RetryNow or the next launch tries again.
                _retriesExhausted = true;
                return;
            }
            var delay = _retryDelays[_retryAttempt++];
            _retryTimer = new Timer(_ => OnRetryTimer(), null, delay, Timeout.InfiniteTimeSpan);
        }
    }

    /// <summary>
    /// Stops monitoring. Returns within a bounded wait even if an acquisition ignores cancellation.
    /// </summary>
    /// <remarks>
    /// No notification starts after this has marked the monitor disposed; one already running is not
    /// waited for, because it may be dispatching to the thread calling Dispose.
    /// </remarks>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            _debounceTimer?.Dispose();
            _retryTimer?.Dispose();
            _retryTimer = null;
        }
        _source.SurfaceChanged -= OnSurfaceChanged;
        // Abort an in-flight scan first: Dispose runs on the UI thread, and waiting for a full
        // signature-verifying rescan to finish would freeze the window it is closing.
        _lifetime.Cancel();
        if (_scanGate.TryEnter(_disposeWait))
        {
            try
            {
                CompleteDisposalLocked();
            }
            finally
            {
                _scanGate.Exit();
            }
        }
        // Otherwise the scan holding the gate completes disposal as it leaves (CompleteDisposalIfIdle).
    }

    private void CompleteDisposalIfIdle()
    {
        lock (_gate)
        {
            if (!_disposed || _cleanupDone)
            {
                return;
            }
        }
        if (_scanGate.TryEnter())
        {
            try
            {
                CompleteDisposalLocked();
            }
            finally
            {
                _scanGate.Exit();
            }
        }
    }

    /// <summary>Runs once, holding the scan gate, so no acquisition is still using shared state.</summary>
    private void CompleteDisposalLocked()
    {
        lock (_gate)
        {
            if (_cleanupDone)
            {
                return;
            }
            _cleanupDone = true;
        }
        try
        {
            _source.Dispose();
        }
        catch (Exception ex) when (!IsCatastrophic(ex))
        {
            RecordFault(PersistenceMonitorOperation.SourceShutdown, ex);
        }
        // Save the final known baseline for next launch — but only if it was actually seeded, so an
        // early/failed start never overwrites a good baseline with an empty one.
        if (_core.IsSeeded)
        {
            TrySaveBaseline();
        }
    }

    private sealed class PendingNotification(PersistenceEvent ev)
    {
        public PersistenceEvent Event { get; } = ev;
        public int Attempts { get; set; }
        public HashSet<Delegate> DeliveredTo { get; } = [];
    }
}
