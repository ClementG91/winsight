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

    /// <summary>
    /// How long the detector stays quiet after firing, when nobody acknowledges it.
    /// </summary>
    /// <remarks>
    /// <b>Why a cooldown and not just the latch.</b> The latch already stops one burst producing
    /// twelve alerts - but the caller resets it as soon as it has notified, so a genuine mass
    /// encryption, which keeps producing bursts for as long as it runs, produced a stream of alerts
    /// indistinguishable from a false positive repeating. The operator cannot tell "this fired
    /// twelve times because twelve different things happened" from "this fired twelve times because
    /// one thing is still happening".
    ///
    /// With a cooldown the second reading is a single alert followed by silence, and the count of
    /// suppressed bursts says how much was still going on - which is the fact worth having.
    /// </remarks>
    public static readonly TimeSpan DefaultCooldown = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The most observations the window will hold before it starts discarding duplicates.
    /// </summary>
    /// <remarks>
    /// The class documents itself as bounded, and it was - but only <i>after</i> it fired. Before
    /// that, every notification inside the window was retained, and Windows reports many
    /// notifications for one file being written. A single process rewriting one file in a loop grows
    /// this without limit for as long as it keeps below the distinct-file threshold, which is
    /// exactly the shape of a program that is not ransomware.
    ///
    /// Only duplicate observations are ever discarded - see <c>TrimDuplicates</c> - so the distinct
    /// count the threshold is compared against cannot be lowered by the cap.
    /// </remarks>
    private const int MaxObservations = 4096;

    /// <summary>
    /// Entries examined from the front of the window per arrival, so trimming stays constant-time.
    /// </summary>
    /// <remarks>
    /// The budget has to exceed the distinct-file threshold for the window to stay capped, and it
    /// does by a wide margin: only an entry that is the sole observation of its path is skipped
    /// rather than dropped, and there can never be more of those than the distinct count - which,
    /// at the threshold, has already fired and stopped accumulating.
    /// </remarks>
    private const int TrimBudget = 64;

    private readonly int _threshold;
    private readonly TimeSpan _window;
    private readonly TimeSpan _cooldown;
    private DateTimeOffset _firedAt;
    private int _suppressed;
    // A linked list rather than a queue, because trimming has to remove an entry from inside the
    // window while leaving the rest in the order they arrived. See TrimDuplicates.
    private readonly LinkedList<Observation> _recent = new();

    /// <summary>
    /// How many observations in the window name each path, so the distinct count is maintained as
    /// events arrive rather than recomputed from scratch on each one.
    /// </summary>
    /// <remarks>
    /// <b>Why this replaced a HashSet built per event.</b> The distinct count was recomputed by
    /// walking the whole window and allocating a fresh set, on every single observation - so the
    /// work per event grew with the number of events already in the window, and the total cost of a
    /// burst grew with its square. The one moment that matters is mass encryption, when thousands of
    /// notifications arrive in the three-second window, and that is precisely when the detector was
    /// slowest. A detector that becomes the bottleneck during the event it exists to catch is a
    /// detector that arrives late.
    /// </remarks>
    private readonly Dictionary<string, int> _byPath = new(StringComparer.OrdinalIgnoreCase);

    private readonly Lock _gate = new();
    private int _unnamed;
    private bool _fired;

    public RansomwareBurstDetector(
        int threshold = DefaultThreshold, TimeSpan? window = null, TimeSpan? cooldown = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(threshold, 1);
        _threshold = threshold;
        _window = window ?? DefaultWindow;
        _cooldown = cooldown ?? DefaultCooldown;
    }

    /// <summary>
    /// Bursts that crossed the threshold during a cooldown and were not alerted on.
    /// </summary>
    /// <remarks>
    /// Non-zero means the activity did not stop. It is the number that separates "one alert because
    /// one thing happened" from "one alert because something is still happening", and it is
    /// deliberately reported rather than silently dropped.
    /// </remarks>
    public int SuppressedBursts
    {
        get { lock (_gate) { return _suppressed; } }
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
            // Inside the cooldown the detector still counts, still latches, and stays quiet. The
            // caller resets the latch as soon as it has notified, so without this a mass encryption
            // - which keeps producing bursts for as long as it runs - produced a stream of alerts
            // indistinguishable from a false positive repeating.
            var cooling = _firedAt != default && atUtc - _firedAt < _cooldown;

            if (kind == RansomwareSignalKind.CanaryTouched)
            {
                _fired = true;
                if (cooling)
                {
                    _suppressed++;
                    return false;
                }
                _firedAt = atUtc;
                return true;
            }

            Admit(new Observation(atUtc, path));
            // The window is in ascending time order, so expiry stops at the first entry still
            // inside it. TrimDuplicates is what keeps that ordering true.
            while (_recent.First is { } oldest && atUtc - oldest.Value.At > _window)
            {
                _recent.RemoveFirst();
                Retire(oldest.Value);
            }
            TrimDuplicates();

            if (DistinctFilesInWindow() >= _threshold)
            {
                _fired = true;
                if (cooling)
                {
                    _suppressed++;
                    return false;
                }
                _firedAt = atUtc;
                return true;
            }
            return false;
        }
    }

    /// <summary>
    /// How many distinct files the window covers. Maintained incrementally, so reading it is free.
    /// </summary>
    private int DistinctFilesInWindow() => _byPath.Count + _unnamed;

    /// <summary>Adds an observation to the window and to the running distinct count.</summary>
    private void Admit(Observation observation)
    {
        _recent.AddLast(observation);
        if (observation.Path is { Length: > 0 } path)
        {
            _byPath[path] = _byPath.TryGetValue(path, out var seen) ? seen + 1 : 1;
        }
        else
        {
            // A signal with no path still counts as its own event, so a caller that cannot name the
            // file is not silently ignored.
            _unnamed++;
        }
    }

    /// <summary>Removes an observation that has aged out, and its contribution to the count.</summary>
    private void Retire(Observation observation)
    {
        if (observation.Path is { Length: > 0 } path)
        {
            // Absent means the bookkeeping already retired it. Decrementing anyway would leave a
            // count of -1 behind, and the distinct count is the dictionary's size, so a phantom
            // entry inflates the very number the threshold is compared against.
            if (!_byPath.TryGetValue(path, out var seen))
            {
                return;
            }
            if (seen <= 1)
            {
                _byPath.Remove(path);
            }
            else
            {
                _byPath[path] = seen - 1;
            }
        }
        else if (_unnamed > 0)
        {
            _unnamed--;
        }
    }

    /// <summary>
    /// Discards the oldest <i>duplicate</i> observations once the window holds more than it needs.
    /// </summary>
    /// <remarks>
    /// Only an observation naming a path the window still holds another of is dropped, so the
    /// distinct count - the number the threshold is compared against - is never lowered by this.
    ///
    /// <b>Why entries are removed in place rather than rotated.</b> The first version dequeued the
    /// oldest entry and, when it was the sole observation of its path, put it back at the end so its
    /// distinct count would not be lost. That silently broke the invariant the rest of the class
    /// rests on - the window is in ascending time order, and expiry stops at the first entry still
    /// inside it. A rotated entry sits behind newer ones, expiry never reaches it, and it goes on
    /// being counted as a distinct file indefinitely: the threshold was then reached with one fewer
    /// real file than it claims to require, in the one detector that must not cry wolf. Skipping
    /// such an entry where it lies keeps both the ordering and the count.
    ///
    /// <b>Why it still terminates.</b> Each arrival adds one entry and this examines up to
    /// <see cref="TrimBudget"/> from the front. If any of those names a path the window holds twice,
    /// it is removed and the window does not grow. The only way all of them are sole observations is
    /// that the front alone holds <see cref="TrimBudget"/> distinct files - far past the threshold,
    /// where the detector has already fired and stopped accumulating.
    /// </remarks>
    private void TrimDuplicates()
    {
        if (_recent.Count <= MaxObservations)
        {
            return;
        }
        var node = _recent.First;
        var budget = TrimBudget;
        while (node is not null && budget-- > 0 && _recent.Count > MaxObservations)
        {
            var next = node.Next;
            if (node.Value.Path is { Length: > 0 } path
                && _byPath.TryGetValue(path, out var seen) && seen > 1)
            {
                _byPath[path] = seen - 1;
                _recent.Remove(node);
            }
            node = next;
        }
    }

    /// <summary>Re-arms after the operator has acknowledged, so a later burst fires again.</summary>
    public void Reset()
    {
        lock (_gate)
        {
            _fired = false;
            _recent.Clear();
            _byPath.Clear();
            _unnamed = 0;
        }
    }

    private readonly record struct Observation(DateTimeOffset At, string? Path);
}
