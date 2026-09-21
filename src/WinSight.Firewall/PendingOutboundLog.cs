namespace WinSight.Firewall;

/// <summary>An application seen reaching the network that the operator has never ruled on.</summary>
/// <param name="ExecutablePath">The canonical executable, the identity every policy is keyed on.</param>
/// <param name="LastRemote">The most recent destination it reached, as evidence for the decision.</param>
/// <param name="FirstSeenUtc">When it was first observed.</param>
/// <param name="LastSeenUtc">When it was last observed.</param>
/// <param name="Observations">How many connections were attributed to it.</param>
public sealed record PendingOutboundApp(
    string ExecutablePath,
    string LastRemote,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    int Observations);

/// <summary>
/// The set of applications observed reaching the network with no policy behind them, waiting for
/// the operator to allow or block them.
/// </summary>
/// <remarks>
/// This is the memory behind "tell me when something new talks to the internet". It is deliberately
/// an observation log and nothing more: it never decides, never blocks, and holds no engine. The
/// decision stays with the operator, and enforcing it stays with the privileged service.
///
/// Two properties matter more than they look:
///
/// <b>It is bounded and rotating.</b> Observations arrive from an ETW callback on every outbound
/// connect, so an unbounded set is a memory-growth primitive that any process could drive. At
/// <see cref="MaxPendingApps"/> distinct apps, a new identity replaces the least recently observed
/// identity. Keeping the first full set forever would be worse: an attacker could pre-fill every
/// slot and permanently blind the operator to every application that starts afterwards. LRU gives
/// every arrival a bounded opportunity to be seen while naturally retaining applications that keep
/// talking. No bounded sample can retain every identity during an unbounded flood, so evictions and
/// their aggregated observations remain explicit coverage loss.
///
/// <b>It never drops silently.</b> Capacity drops, connections without a safe executable identity,
/// native ETW loss, and a terminal observer failure all contribute to
/// <see cref="UnrecordedObservations"/>, so a
/// caller never presents a quiet or truncated list as complete. <see cref="DroppedApps"/> remains
/// available separately for capacity diagnostics.
/// </remarks>
public sealed class PendingOutboundLog
{
    /// <summary>
    /// The cap on distinct unresolved apps. Reaching it already means something pathological: a
    /// normal machine has a handful of unruled apps, not a hundred.
    /// </summary>
    public const int MaxPendingApps = 128;

    private readonly Dictionary<string, PendingEntry> _pending =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly LinkedList<string> _recency = [];
    private readonly Lock _gate = new();
    private long _dropped;
    private long _evictedObservations;
    private int _unattributed;
    private long _lostEvents;
    private bool _observerUnavailable;

    /// <summary>How many unresolved app identities were evicted because the log was full.</summary>
    public int DroppedApps
    {
        get { lock (_gate) { return ClampToInt(_dropped); } }
    }

    /// <summary>Aggregated observations removed with capacity-evicted identities.</summary>
    public int EvictedObservations
    {
        get { lock (_gate) { return ClampToInt(_evictedObservations); } }
    }

    /// <summary>Connections observed without an absolute executable identity safe for policy.</summary>
    public int UnattributedObservations
    {
        get { lock (_gate) { return _unattributed; } }
    }

    /// <summary>Native ETW events the outbound session reports losing under load.</summary>
    public long LostEvents
    {
        get { lock (_gate) { return _lostEvents; } }
    }

    /// <summary>
    /// A conservative lower bound on outbound observations that the rulable pending list does not
    /// represent. The terminal-health marker contributes one because the number of events missed
    /// after observation stops is unknowable; zero must remain reserved for a healthy, complete
    /// observation path.
    /// </summary>
    public int UnrecordedObservations
    {
        get
        {
            lock (_gate)
            {
                var total = SaturatingAdd(_evictedObservations, _unattributed);
                total = SaturatingAdd(total, _lostEvents);
                total = SaturatingAdd(total, _observerUnavailable ? 1 : 0);
                return ClampToInt(total);
            }
        }
    }

    /// <summary>
    /// Records the session's cumulative native loss counter. The maximum is retained because
    /// status polling and event callbacks may race, and an older snapshot must never reduce loss.
    /// </summary>
    public void RecordLostEvents(long cumulativeLostEvents)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(cumulativeLostEvents);
        lock (_gate)
        {
            _lostEvents = Math.Max(_lostEvents, cumulativeLostEvents);
        }
    }

    /// <summary>Records a connection that had no absolute executable identity safe for policy.</summary>
    public void RecordUnattributed()
    {
        lock (_gate)
        {
            if (_unattributed < int.MaxValue)
            {
                _unattributed++;
            }
        }
    }

    /// <summary>Marks the observation pump terminally unavailable for this service lifetime.</summary>
    public void MarkObserverUnavailable()
    {
        lock (_gate)
        {
            _observerUnavailable = true;
        }
    }

    /// <summary>
    /// Records that <paramref name="executablePath"/> reached <paramref name="remote"/>. Returns
    /// true only the first time an app is recorded, so a caller can notify once per app rather
    /// than once per connection.
    /// </summary>
    public bool Observe(string executablePath, string remote, DateTimeOffset seenUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(remote);
        var path = OutboundPolicyEvaluator.CanonicalPath(executablePath);

        lock (_gate)
        {
            if (_pending.TryGetValue(path, out var existing))
            {
                existing.App = existing.App with
                {
                    LastRemote = remote,
                    LastSeenUtc = seenUtc > existing.App.LastSeenUtc ? seenUtc : existing.App.LastSeenUtc,
                    Observations = existing.App.Observations < int.MaxValue
                        ? existing.App.Observations + 1
                        : int.MaxValue,
                };
                MarkMostRecent(existing);
                return false;
            }

            if (_pending.Count >= MaxPendingApps)
            {
                EvictLeastRecent();
            }

            var recencyNode = _recency.AddLast(path);
            _pending[path] = new PendingEntry(
                new PendingOutboundApp(path, remote, seenUtc, seenUtc, Observations: 1),
                recencyNode);
            return true;
        }
    }

    /// <summary>
    /// Forgets an app because the operator ruled on it, or because it no longer needs a ruling.
    /// Returns true when something was actually forgotten.
    /// </summary>
    public bool Resolve(string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        var path = OutboundPolicyEvaluator.CanonicalPath(executablePath);
        lock (_gate)
        {
            if (!_pending.Remove(path, out var removed))
            {
                return false;
            }

            _recency.Remove(removed.RecencyNode);
            return true;
        }
    }

    /// <summary>
    /// The unresolved apps, most recently seen first so the newest arrival is the one an operator
    /// reads before anything else.
    /// </summary>
    public IReadOnlyList<PendingOutboundApp> Snapshot()
    {
        lock (_gate)
        {
            return _pending.Values
                .Select(entry => entry.App)
                .OrderByDescending(app => app.LastSeenUtc)
                .ThenBy(app => app.ExecutablePath, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
    }

    private void MarkMostRecent(PendingEntry entry)
    {
        _recency.Remove(entry.RecencyNode);
        _recency.AddLast(entry.RecencyNode);
    }

    private void EvictLeastRecent()
    {
        var node = _recency.First
            ?? throw new InvalidOperationException("A full pending log has no eviction candidate.");
        if (!_pending.Remove(node.Value, out var evicted))
        {
            throw new InvalidOperationException("Pending-log recency index is inconsistent.");
        }

        _recency.Remove(node);
        _dropped = SaturatingAdd(_dropped, 1);
        _evictedObservations = SaturatingAdd(_evictedObservations, evicted.App.Observations);
    }

    private static int ClampToInt(long value) =>
        value >= int.MaxValue ? int.MaxValue : (int)value;

    private static long SaturatingAdd(long left, long right) =>
        left >= long.MaxValue - right ? long.MaxValue : left + right;

    private sealed class PendingEntry(
        PendingOutboundApp app,
        LinkedListNode<string> recencyNode)
    {
        public PendingOutboundApp App { get; set; } = app;

        public LinkedListNode<string> RecencyNode { get; } = recencyNode;
    }
}
