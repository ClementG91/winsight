namespace WinSight.Persistence;

/// <summary>
/// The stateful-but-pure heart of real-time persistence monitoring: it owns the baseline of known
/// identities and the change log, and turns "here is a fresh scan" into "here is what is newly
/// present". No threads, no timers, no I/O — the <see cref="PersistenceMonitor"/> wrapper supplies
/// scans and a clock, so every decision here is unit-testable.
/// </summary>
public sealed class PersistenceMonitorCore
{
    private readonly PersistenceChangeLog _log;
    private readonly HashSet<PersistenceIdentity> _baseline = new();
    private readonly Lock _gate = new();
    private bool _seeded;

    public PersistenceMonitorCore(PersistenceChangeLog? log = null)
    {
        _log = log ?? new PersistenceChangeLog();
    }

    /// <summary>The observation log holding the surfaced arrivals (and the dropped count).</summary>
    public PersistenceChangeLog Log => _log;

    /// <summary>True once the baseline has been seeded (by <see cref="SeedBaseline"/> or the first scan).</summary>
    public bool IsSeeded
    {
        get { lock (_gate) { return _seeded; } }
    }

    /// <summary>
    /// A snapshot of the current baseline identities, for persisting across runs so the next launch
    /// can tell what changed while WinSight was not running.
    /// </summary>
    public IReadOnlyCollection<PersistenceIdentity> CurrentBaseline
    {
        get { lock (_gate) { return _baseline.ToArray(); } }
    }

    /// <summary>
    /// Seeds the baseline from an initial full scan WITHOUT surfacing anything. Pre-existing
    /// persistence is not news; without this every machine would alert on first launch. Idempotent:
    /// only the first seeding takes effect.
    /// </summary>
    public void SeedBaseline(IReadOnlyList<AutostartEntry> initialScan)
    {
        ArgumentNullException.ThrowIfNull(initialScan);
        lock (_gate)
        {
            if (_seeded)
            {
                return;
            }
            SeedLocked(initialScan);
        }
    }

    /// <summary>
    /// Reconciles a fresh scan against the baseline. Identities not in the baseline are recorded in
    /// the log and returned. This overload accepts a complete full snapshot: confirmed removals
    /// leave the baseline, allowing a later reappearance to notify again. If the baseline
    /// was never seeded, the first scan seeds it silently (a first scan is never news). Returns only
    /// arrivals recorded in this reconciliation, including reappearances after confirmed removal.
    /// </summary>
    public IReadOnlyList<PersistenceEvent> Reconcile(
        IReadOnlyList<AutostartEntry> freshScan, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(freshScan);
        lock (_gate)
        {
            if (!_seeded)
            {
                SeedLocked(freshScan);
                return Array.Empty<PersistenceEvent>();
            }

            return ReconcileLocked(freshScan, nowUtc, confirmsAbsence: null);
        }
    }

    /// <summary>
    /// Reconciles a scoped scan. Only sources explicitly confirmed complete may lose identities;
    /// unscanned, failed, and partially readable sources keep their previous observations.
    /// </summary>
    public IReadOnlyList<PersistenceEvent> Reconcile(PersistenceScanResult scan, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(scan);
        lock (_gate)
        {
            if (!_seeded)
            {
                SeedLocked(scan.Entries);
                return Array.Empty<PersistenceEvent>();
            }
            return ReconcileLocked(scan.Entries, nowUtc, id => scan.ConfirmsAbsence(id.Source, id.Location));
        }
    }

    /// <summary>
    /// Reconciles the current scan against a baseline persisted from a previous run, so persistence
    /// that appeared while WinSight was NOT running surfaces on this launch. New identities (present
    /// now, absent from the persisted baseline) are recorded and returned. Afterwards the baseline is
    /// set to exactly the current state, so entries that vanished while WinSight was off drop out and
    /// cannot spuriously re-alert.
    /// </summary>
    public IReadOnlyList<PersistenceEvent> ReconcileFromPersistedBaseline(
        IReadOnlySet<PersistenceIdentity> persistedBaseline,
        IReadOnlyList<AutostartEntry> currentScan,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(persistedBaseline);
        ArgumentNullException.ThrowIfNull(currentScan);
        lock (_gate)
        {
            _baseline.Clear();
            foreach (var id in persistedBaseline)
            {
                _baseline.Add(id);
            }
            _seeded = true;

            return ReconcileLocked(currentScan, nowUtc, confirmsAbsence: null);
        }
    }

    /// <summary>Restores a baseline without treating failed startup sources as empty.</summary>
    public IReadOnlyList<PersistenceEvent> ReconcileFromPersistedBaseline(
        IReadOnlySet<PersistenceIdentity> persistedBaseline,
        PersistenceScanResult currentScan,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(persistedBaseline);
        ArgumentNullException.ThrowIfNull(currentScan);
        lock (_gate)
        {
            _baseline.Clear();
            _baseline.UnionWith(persistedBaseline);
            _seeded = true;
            return ReconcileLocked(currentScan.Entries, nowUtc,
                id => currentScan.ConfirmsAbsence(id.Source, id.Location));
        }
    }

    private IReadOnlyList<PersistenceEvent> ReconcileLocked(
        IReadOnlyList<AutostartEntry> freshScan, DateTimeOffset nowUtc,
        Func<PersistenceIdentity, bool>? confirmsAbsence)
    {
        var diff = PersistenceDiffEngine.Diff(_baseline, freshScan);
        foreach (var removed in diff.Removed)
        {
            if (confirmsAbsence is null || confirmsAbsence(removed))
            {
                _baseline.Remove(removed);
            }
        }
        if (diff.Added.Count == 0)
        {
            return Array.Empty<PersistenceEvent>();
        }

        var detected = new List<PersistenceEvent>(diff.Added.Count);
        foreach (var entry in diff.Added)
        {
            // Add to the baseline regardless of whether the (bounded) log had room, so a full log
            // does not re-diff and re-count the same arrival on every subsequent scan.
            var identity = PersistenceIdentity.FromEntry(entry);
            _baseline.Add(identity);
            // The log is a bounded display list that nothing acknowledges. Reporting only what it had
            // room for silenced every arrival after the 256th in a long session, while the baseline
            // absorbed them. The arrival is reported either way; a full list only counts it.
            detected.Add(_log.RecordArrival(entry, nowUtc)
                ?? new PersistenceEvent(identity, entry, nowUtc, nowUtc, Observations: 1));
        }
        return detected;
    }

    private void SeedLocked(IReadOnlyList<AutostartEntry> scan)
    {
        foreach (var entry in scan)
        {
            _baseline.Add(PersistenceIdentity.FromEntry(entry));
        }
        _seeded = true;
    }
}
