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
    /// the log and returned, and are added to the baseline so each is reported once. If the baseline
    /// was never seeded, the first scan seeds it silently (a first scan is never news). Returns only
    /// entries recorded for the first time.
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

            var diff = PersistenceDiffEngine.Diff(_baseline, freshScan);
            if (diff.Added.Count == 0)
            {
                return Array.Empty<PersistenceEvent>();
            }

            var detected = new List<PersistenceEvent>(diff.Added.Count);
            foreach (var entry in diff.Added)
            {
                // Add to the baseline regardless of whether the (bounded) log had room, so a full
                // log does not re-diff and re-count the same arrival on every subsequent scan.
                _baseline.Add(PersistenceIdentity.FromEntry(entry));
                var recorded = _log.Observe(entry, nowUtc);
                if (recorded is not null)
                {
                    detected.Add(recorded);
                }
            }
            return detected;
        }
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
