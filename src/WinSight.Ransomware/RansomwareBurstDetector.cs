namespace WinSight.Ransomware;

/// <summary>A file-activity signal the burst detector counts.</summary>
public enum RansomwareSignalKind
{
    /// <summary>A freshly written file whose content looks encrypted (high Shannon entropy).</summary>
    HighEntropyWrite,

    /// <summary>A file was renamed (ransomware commonly appends an extension to every file).</summary>
    Rename,

    /// <summary>A file was deleted (some families delete the original after writing the encrypted copy).</summary>
    Delete,

    /// <summary>A decoy/canary file was touched — high confidence on its own.</summary>
    CanaryTouched,
}

/// <summary>
/// Detects a burst of ransomware-like file activity in a sliding time window. Ransomware's tell is
/// volume and speed — many files encrypted, renamed, or deleted in seconds — so this counts recent
/// suspicious signals and fires once when they cross a threshold within the window. A touched canary
/// fires immediately: a decoy has no legitimate reason to change.
/// </summary>
/// <remarks>
/// Pure and unit-testable: the caller supplies each signal's timestamp (no internal clock), and the
/// window is a fixed span. It is bounded — once it has fired it stops accumulating until
/// <see cref="Reset"/>, so a flood cannot grow its state without limit. It decides and alerts only;
/// it never touches a file.
/// </remarks>
public sealed class RansomwareBurstDetector
{
    /// <summary>Distinct files touched within the window needed to call it a burst.</summary>
    public const int DefaultThreshold = 12;

    /// <summary>The sliding window over which suspicious events are counted.</summary>
    public static readonly TimeSpan DefaultWindow = TimeSpan.FromSeconds(3);

    private readonly int _threshold;
    private readonly TimeSpan _window;
    private readonly Queue<Observation> _recent = new();
    private readonly Lock _gate = new();
    private bool _fired;

    public RansomwareBurstDetector(int threshold = DefaultThreshold, TimeSpan? window = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(threshold, 1);
        _threshold = threshold;
        _window = window ?? DefaultWindow;
    }

    /// <summary>Distinct files touched within the window.</summary>
    public int RecentCount
    {
        get { lock (_gate) { return DistinctFilesInWindow(); } }
    }

    /// <summary>True once the detector has fired and is waiting to be acknowledged.</summary>
    public bool HasFired
    {
        get { lock (_gate) { return _fired; } }
    }

    /// <summary>
    /// Records a signal at <paramref name="atUtc"/>. Returns true exactly once — when this signal is
    /// the one that crosses the burst threshold, or is a touched canary — so the caller alerts once
    /// per burst rather than once per file. Returns false thereafter until <see cref="Reset"/>.
    /// </summary>
    public bool Observe(RansomwareSignalKind kind, DateTimeOffset atUtc) =>
        Observe(kind, atUtc, path: null);

    /// <summary>
    /// The same, counting <b>distinct files</b> rather than raw events.
    /// </summary>
    /// <remarks>
    /// <b>Why the path matters.</b> Ransomware's tell is volume across <i>many</i> files. Windows
    /// reports several change notifications for one file being written - a large document produces a
    /// stream of them on its own - so counting events made a single big save look like a burst, and
    /// two Excel workbooks autosaving together were enough to reach twelve. Counting distinct paths
    /// keeps the signal (many files touched quickly) and removes the noise (one file touched many
    /// times), without weakening the threshold.
    ///
    /// A signal with no path still counts as its own event, so a caller that cannot name the file is
    /// not silently ignored.
    /// </remarks>
    public bool Observe(RansomwareSignalKind kind, DateTimeOffset atUtc, string? path)
    {
        lock (_gate)
        {
            if (_fired)
            {
                return false; // already alerted this burst; wait for the operator to acknowledge
            }

            if (kind == RansomwareSignalKind.CanaryTouched)
            {
                _fired = true;
                return true;
            }

            _recent.Enqueue(new Observation(atUtc, path));
            while (_recent.Count > 0 && atUtc - _recent.Peek().At > _window)
            {
                _recent.Dequeue();
            }

            if (DistinctFilesInWindow() >= _threshold)
            {
                _fired = true;
                return true;
            }
            return false;
        }
    }

    /// <summary>
    /// How many distinct files the window covers. Bounded by the queue, which the window bounds.
    /// </summary>
    private int DistinctFilesInWindow()
    {
        var named = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var unnamed = 0;
        foreach (var observation in _recent)
        {
            if (observation.Path is { Length: > 0 } path)
            {
                named.Add(path);
            }
            else
            {
                unnamed++;
            }
        }
        return named.Count + unnamed;
    }

    /// <summary>Re-arms after the operator has acknowledged, so a later burst fires again.</summary>
    public void Reset()
    {
        lock (_gate)
        {
            _fired = false;
            _recent.Clear();
        }
    }

    private readonly record struct Observation(DateTimeOffset At, string? Path);
}
