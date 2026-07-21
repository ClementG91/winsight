namespace WinSight.Attribution;

/// <summary>A write observed with its author, already translated to WinSight's path forms.</summary>
/// <param name="WhenUtc">When the kernel reported the write.</param>
/// <param name="ProcessId">The process that performed it.</param>
/// <param name="ExecutablePath">That process's executable, captured while it was alive.</param>
/// <param name="Target">The file path or registry key written.</param>
public sealed record WriteObservation(
    DateTimeOffset WhenUtc,
    int ProcessId,
    string ExecutablePath,
    string Target);

/// <summary>
/// Remembers recent writes just long enough to answer "who did this?" when a detection lands.
/// </summary>
/// <remarks>
/// A detection never arrives at the instant of the write that caused it: Guardian re-scans the
/// surface that changed, and ETW itself delivers late, so the answer has to be looked up backwards
/// in time. This keeps a bounded, time-windowed log to do exactly that, and nothing more.
///
/// It is deliberately separate from the ETW session and takes every time as a parameter, so the
/// correlation rules — how far back to look, what counts as the same target, which write wins when
/// several match — are unit-testable without elevation or a live trace. That matters because these
/// rules are where attribution gets things quietly wrong, and a wrong name next to a security
/// finding is worse than no name.
///
/// Bounded on two axes: entries older than the retention window are dropped, and a hard ceiling
/// stops a process writing in a loop from growing this without limit. Under pressure the oldest
/// observations go first, because the newest are the ones a detection is about to ask for.
/// </remarks>
public sealed class WriteAttributionIndex
{
    /// <summary>How far back a detection may reach. Covers Guardian's re-scan plus ETW lag.</summary>
    public static readonly TimeSpan DefaultRetention = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Tolerance for a write timestamped just after the detection. ETW timestamps and the
    /// detector's clock are not the same source, so a strict "write before detection" comparison
    /// would drop correct attributions at the boundary.
    /// </summary>
    public static readonly TimeSpan ForwardTolerance = TimeSpan.FromSeconds(2);

    /// <summary>A ceiling on remembered writes, so a write loop cannot exhaust memory.</summary>
    public const int MaxObservations = 4096;

    private readonly TimeSpan _retention;
    private readonly LinkedList<WriteObservation> _observations = new();
    private readonly Lock _gate = new();

    public WriteAttributionIndex(TimeSpan? retention = null) =>
        _retention = retention is { } value && value > TimeSpan.Zero ? value : DefaultRetention;

    public int Count
    {
        get { lock (_gate) { return _observations.Count; } }
    }

    /// <summary>Remembers a write. Oldest observations are dropped once the ceiling is reached.</summary>
    public void Record(WriteObservation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);
        if (string.IsNullOrWhiteSpace(observation.Target)
            || string.IsNullOrWhiteSpace(observation.ExecutablePath))
        {
            // An observation missing either half cannot attribute anything; keeping it would only
            // consume a slot a usable one needs.
            return;
        }

        lock (_gate)
        {
            _observations.AddLast(observation);
            while (_observations.Count > MaxObservations)
            {
                _observations.RemoveFirst();
            }
        }
    }

    /// <summary>
    /// The most recent write that can explain a detection on <paramref name="target"/> at
    /// <paramref name="detectedAtUtc"/>, or null when nothing observed accounts for it.
    /// </summary>
    /// <remarks>
    /// Null is a normal answer, not a failure: the writer may have acted before monitoring started,
    /// or through a path this never saw. Reporting the wrong process would be the worse outcome.
    /// </remarks>
    public WriteObservation? Attribute(string? target, DateTimeOffset detectedAtUtc)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            return null;
        }

        var earliest = detectedAtUtc - _retention;
        var latest = detectedAtUtc + ForwardTolerance;
        lock (_gate)
        {
            // Newest first: the write that best explains a detection is the last one before it.
            for (var node = _observations.Last; node is not null; node = node.Previous)
            {
                var observation = node.Value;
                if (observation.WhenUtc > latest)
                {
                    continue;
                }
                if (observation.WhenUtc < earliest)
                {
                    // Ordered by arrival, so everything further back is older still.
                    break;
                }
                if (Matches(observation.Target, target))
                {
                    return observation;
                }
            }
        }
        return null;
    }

    /// <summary>Forgets observations older than the retention window.</summary>
    public void Prune(DateTimeOffset nowUtc)
    {
        var earliest = nowUtc - _retention;
        lock (_gate)
        {
            while (_observations.First is { } first && first.Value.WhenUtc < earliest)
            {
                _observations.RemoveFirst();
            }
        }
    }

    /// <summary>
    /// Whether an observed write explains a detection on <paramref name="detectionTarget"/>.
    /// </summary>
    /// <remarks>
    /// The two are not always spelled identically. A kernel session reports the registry <i>key</i>
    /// that changed, while a finding names the key plus the value inside it
    /// (<c>HKCU\...\Run [Foo]</c>), and a startup-folder finding may carry a display suffix too. An
    /// observation therefore also matches when the detection target continues past it at a
    /// boundary — but never on a bare character boundary, so <c>...\Run</c> does not match a
    /// different key that merely starts with the same text.
    /// </remarks>
    private static bool Matches(string observed, string detectionTarget)
    {
        if (detectionTarget.Equals(observed, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        if (!detectionTarget.StartsWith(observed, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        var next = detectionTarget[observed.Length];
        return next is '\\' or ' ' or '[';
    }
}
