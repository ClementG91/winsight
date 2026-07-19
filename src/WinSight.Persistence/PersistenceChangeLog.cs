namespace WinSight.Persistence;

/// <summary>A newly-observed persistence entry awaiting the operator's attention.</summary>
/// <param name="Identity">Its canonical identity, the dedup key.</param>
/// <param name="Entry">The resolved, signature-checked autostart entry as last seen.</param>
/// <param name="FirstSeenUtc">When it was first observed appearing.</param>
/// <param name="LastSeenUtc">When it was last re-observed.</param>
/// <param name="Observations">How many scans re-confirmed it.</param>
public sealed record PersistenceEvent(
    PersistenceIdentity Identity,
    AutostartEntry Entry,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    int Observations)
{
    /// <summary>
    /// True when the arrival is worth surfacing loudly (image missing, unsigned, or
    /// signed-but-untrusted). A signed-trusted arrival is real news but not alarming, so it stays
    /// off the alert path. This reuses the scan's triage (<see cref="AutostartEntry.IsSuspicious"/>);
    /// it does not invent a second verdict.
    /// </summary>
    public bool IsNotable => Entry.IsSuspicious;
}

/// <summary>
/// The set of persistence entries observed appearing since the baseline, waiting for the operator
/// to see them. The persistence analog of <c>PendingOutboundLog</c>: an observation log and nothing
/// more. It never removes anything from the system and holds no scanner — recognition only.
/// </summary>
/// <remarks>
/// <b>It is bounded.</b> Arrivals are driven by registry/filesystem change notifications, which a
/// hostile process can fire in a tight loop. At <see cref="MaxChanges"/> distinct entries, further
/// NEW entries are refused rather than evicting existing ones — evicting would let a flood push the
/// one interesting arrival out of the list, exactly what an attacker would want.
///
/// <b>It never drops silently.</b> A refused arrival increments <see cref="DroppedChanges"/> so the
/// UI can say "and more were not recorded" instead of showing a truncated list that looks complete.
/// A security tool that hides its own blind spot is worse than one without the feature.
/// </remarks>
public sealed class PersistenceChangeLog
{
    /// <summary>The cap on distinct recorded arrivals. A normal machine adds persistence rarely.</summary>
    public const int MaxChanges = 256;

    private readonly Dictionary<PersistenceIdentity, PersistenceEvent> _events = new();
    private readonly Lock _gate = new();
    private int _dropped;

    /// <summary>How many distinct arrivals could not be recorded because the log was full.</summary>
    public int DroppedChanges
    {
        get { lock (_gate) { return _dropped; } }
    }

    /// <summary>
    /// Records that <paramref name="entry"/> was observed. Returns the created event only the first
    /// time an identity is recorded (so a caller can notify once per entry), null on a repeat
    /// observation or when the log is full.
    /// </summary>
    public PersistenceEvent? Observe(AutostartEntry entry, DateTimeOffset seenUtc)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var id = PersistenceIdentity.FromEntry(entry);
        lock (_gate)
        {
            if (_events.TryGetValue(id, out var existing))
            {
                _events[id] = existing with
                {
                    Entry = entry,
                    LastSeenUtc = seenUtc > existing.LastSeenUtc ? seenUtc : existing.LastSeenUtc,
                    Observations = existing.Observations + 1,
                };
                return null;
            }

            if (_events.Count >= MaxChanges)
            {
                _dropped++;
                return null;
            }

            var created = new PersistenceEvent(id, entry, seenUtc, seenUtc, Observations: 1);
            _events[id] = created;
            return created;
        }
    }

    /// <summary>Forgets an entry because the operator acknowledged it. True when one was removed.</summary>
    public bool Acknowledge(PersistenceIdentity identity)
    {
        lock (_gate)
        {
            return _events.Remove(identity);
        }
    }

    /// <summary>The recorded arrivals, most recently seen first so the newest reads first.</summary>
    public IReadOnlyList<PersistenceEvent> Snapshot()
    {
        lock (_gate)
        {
            return _events.Values
                .OrderByDescending(e => e.LastSeenUtc)
                .ThenBy(e => e.Entry.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
    }
}
