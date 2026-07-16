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
/// <b>It is bounded.</b> Observations arrive from an ETW callback on every outbound connect, so an
/// unbounded set is a memory-growth primitive that any process could drive. At
/// <see cref="MaxPendingApps"/> distinct apps, further <em>new</em> apps are refused rather than
/// evicting existing ones — evicting would let a flood of noise push the one interesting app out of
/// the list, which is precisely what an attacker would want.
///
/// <b>It never drops silently.</b> A refused observation increments <see cref="DroppedApps"/>, so a
/// caller can say "and more were not recorded" instead of quietly showing a truncated list that
/// looks complete. A security tool that hides its own blind spot is worse than one without the
/// feature.
/// </remarks>
public sealed class PendingOutboundLog
{
    /// <summary>
    /// The cap on distinct unresolved apps. Reaching it already means something pathological: a
    /// normal machine has a handful of unruled apps, not a hundred.
    /// </summary>
    public const int MaxPendingApps = 128;

    private readonly Dictionary<string, PendingOutboundApp> _pending =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _gate = new();
    private int _dropped;

    /// <summary>How many distinct apps could not be recorded because the log was full.</summary>
    public int DroppedApps
    {
        get { lock (_gate) { return _dropped; } }
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
                _pending[path] = existing with
                {
                    LastRemote = remote,
                    LastSeenUtc = seenUtc > existing.LastSeenUtc ? seenUtc : existing.LastSeenUtc,
                    Observations = existing.Observations + 1,
                };
                return false;
            }

            if (_pending.Count >= MaxPendingApps)
            {
                _dropped++;
                return false;
            }

            _pending[path] = new PendingOutboundApp(path, remote, seenUtc, seenUtc, Observations: 1);
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
            return _pending.Remove(path);
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
                .OrderByDescending(app => app.LastSeenUtc)
                .ThenBy(app => app.ExecutablePath, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
    }
}
