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
    // What the baseline has seen in full (WS-70); null when unknown - seeded from bare entries, or
    // restored from a baseline saved without coverage - which keeps the pre-coverage rule.
    private PersistenceCoverageMap? _coverage;
    private int _absorbed;
    // Absorbed since the last TakeCoverageGain (RA-03): what the widened view found, kept until the
    // monitor hands it on, because absorbing without a word hid entries planted while unreadable.
    private readonly List<AutostartEntry> _uncertain = [];
    private int _uncertainUnlisted;
    private DateTimeOffset _uncertainObservedUtc;

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

    /// <summary>What the baseline has seen in full, persisted with it; null while unknown.</summary>
    public PersistenceCoverageMap? CurrentCoverage
    {
        get { lock (_gate) { return _coverage; } }
    }

    /// <summary>
    /// Entries baselined without an alert because their location was read in full for the first time
    /// (for instance the first elevated launch after unelevated ones).
    /// </summary>
    public int AbsorbedOnCoverageGain
    {
        get { lock (_gate) { return _absorbed; } }
    }

    /// <summary>
    /// The entries absorbed since the last call, as one batch to be reported as uncertain rather than
    /// as arrivals, or null when none were. Each absorbed entry is returned once.
    /// </summary>
    public PersistenceCoverageGain? TakeCoverageGain()
    {
        lock (_gate)
        {
            if (_uncertain.Count == 0 && _uncertainUnlisted == 0)
            {
                return null;
            }
            var gain = new PersistenceCoverageGain(_uncertainObservedUtc, _uncertain.ToArray(), _uncertainUnlisted);
            _uncertain.Clear();
            _uncertainUnlisted = 0;
            return gain;
        }
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
    /// Seeds the baseline from an initial scan together with what that scan could read in full, so a
    /// later scan that reads more baselines the difference instead of announcing it.
    /// </summary>
    public void SeedBaseline(PersistenceScanResult initialScan)
    {
        ArgumentNullException.ThrowIfNull(initialScan);
        lock (_gate)
        {
            if (_seeded)
            {
                return;
            }
            SeedLocked(initialScan.Entries);
            _coverage = PersistenceCoverageMap.FromScan(initialScan);
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
                _coverage = PersistenceCoverageMap.FromScan(scan);
                return Array.Empty<PersistenceEvent>();
            }
            var detected = ReconcileLocked(scan.Entries, nowUtc,
                id => scan.ConfirmsAbsence(id.Source, id.Location), NewlyVisibleIn(scan, _coverage));
            if (_coverage is not null)
            {
                _coverage = _coverage.Merge(PersistenceCoverageMap.FromScan(scan));
            }
            return detected;
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
        DateTimeOffset nowUtc) =>
        ReconcileFromPersistedBaseline(persistedBaseline, persistedCoverage: null, currentScan, nowUtc);

    /// <summary>
    /// Restores a baseline saved with its coverage. An entry at a location this scan read in full and
    /// the saved baseline never had is baselined, not announced (WS-70); with no saved coverage every
    /// new entry is announced, as before, and coverage is tracked from this scan on.
    /// </summary>
    public IReadOnlyList<PersistenceEvent> ReconcileFromPersistedBaseline(
        IReadOnlySet<PersistenceIdentity> persistedBaseline,
        PersistenceCoverageMap? persistedCoverage,
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
            var detected = ReconcileLocked(currentScan.Entries, nowUtc,
                id => currentScan.ConfirmsAbsence(id.Source, id.Location),
                NewlyVisibleIn(currentScan, persistedCoverage));
            var scanned = PersistenceCoverageMap.FromScan(currentScan);
            _coverage = persistedCoverage is null ? scanned : persistedCoverage.Merge(scanned);
            return detected;
        }
    }

    /// <summary>
    /// Entries the scan saw at a location read in full, which the baseline had never read in full:
    /// they were there before and simply could not be seen. Null when the baseline's coverage is
    /// unknown, which leaves every arrival announced.
    /// </summary>
    private static Func<PersistenceIdentity, bool>? NewlyVisibleIn(
        PersistenceScanResult scan, PersistenceCoverageMap? baselineCoverage) =>
        baselineCoverage is null
            ? null
            : id => scan.ConfirmsAbsence(id.Source, id.Location) && !baselineCoverage.Covers(id.Source, id.Location);

    private IReadOnlyList<PersistenceEvent> ReconcileLocked(
        IReadOnlyList<AutostartEntry> freshScan, DateTimeOffset nowUtc,
        Func<PersistenceIdentity, bool>? confirmsAbsence,
        Func<PersistenceIdentity, bool>? newlyVisible = null)
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
            if (newlyVisible?.Invoke(identity) == true)
            {
                _absorbed++;
                if (_uncertain.Count < PersistenceCoverageGain.MaxListed)
                {
                    _uncertain.Add(entry);
                }
                else
                {
                    _uncertainUnlisted++;
                }
                _uncertainObservedUtc = nowUtc;
                continue;
            }
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
