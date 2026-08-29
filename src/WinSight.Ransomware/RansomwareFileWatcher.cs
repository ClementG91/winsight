using System.Collections.Concurrent;

namespace WinSight.Ransomware;

/// <summary>Raised once when ransomware-like activity is detected (a touched canary, or a burst).</summary>
public sealed class RansomwareDetectedEventArgs(RansomwareSignalKind kind, string path) : EventArgs
{
    /// <summary>The signal that tripped the detector.</summary>
    public RansomwareSignalKind Kind { get; } = kind;

    /// <summary>The file whose change tripped it.</summary>
    public string Path { get; } = path;
}

/// <summary>
/// Watches a set of directories for ransomware-like file activity and feeds each change through the
/// pure classifier into the bounded <see cref="RansomwareBurstDetector"/>. It raises
/// <see cref="Detected"/> once per burst (or immediately on a touched canary).
/// </summary>
/// <remarks>
/// <b>The failure this was rebuilt around.</b> The detector fires on 12 events in 3 seconds — which
/// is precisely the rate at which Windows overruns a <see cref="FileSystemWatcher"/>'s kernel
/// buffer. That buffer defaulted to 8 KiB (roughly 250 pending events), the
/// <see cref="FileSystemWatcher.Error"/> event was not handled anywhere in the product, and the
/// change callback then did synchronous I/O — opening each new file and reading 4 KiB to score its
/// entropy — before returning. Under real mass encryption the events would be dropped silently, the
/// sliding window would never fill, and the UI would report nothing found at the exact moment the
/// detector was supposed to count. A silent false negative, in the one scenario the feature exists
/// for.
///
/// Three changes, which only make sense together:
/// <list type="number">
/// <item>The buffer is raised to its practical maximum, so far more events survive a burst.</item>
/// <item>Overflow is handled and counted. A dropped event is a hole in coverage, and this codebase's
/// rule everywhere else is that "I could not see" is never reported as "nothing there" — see
/// <see cref="OverflowCount"/>, which the dashboard surfaces.</item>
/// <item>The callback does no I/O. It queues, and a single background worker samples entropy and
/// notifies. Whatever the consumer does with an alert can no longer stall the thread Windows is
/// using to hand over the next event, which was itself a way to cause the overflow.</item>
/// </list>
/// </remarks>
public sealed class RansomwareFileWatcher : IDisposable
{
    /// <summary>
    /// Kernel buffer per watched directory. 64 KiB is the documented practical maximum: beyond it
    /// the buffer must be allocated from non-paged pool, and Windows can fail the watch outright.
    /// </summary>
    public const int WatchBufferBytes = 64 * 1024;

    /// <summary>
    /// Queue depth before changes are dropped. Generous enough to ride out a burst, bounded so a
    /// pathological writer cannot grow this process without limit — the same rule every other
    /// long-lived structure in WinSight follows.
    /// </summary>
    private const int MaxQueuedChanges = 8192;

    private readonly IReadOnlyList<string> _directories;
    private readonly Func<string?, bool> _isCanary;
    private readonly Func<string?, bool> _looksEncrypted;
    private readonly RansomwareBurstDetector _detector;
    private readonly Func<DateTimeOffset> _clock;
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly Lock _gate = new();
    private readonly BlockingCollection<PendingChange> _pending =
        new(new ConcurrentQueue<PendingChange>(), MaxQueuedChanges);
    private Thread? _worker;
    private int _overflows;
    private int _dropped;
    private bool _started;
    private bool _disposed;

    public event EventHandler<RansomwareDetectedEventArgs>? Detected;

    public RansomwareFileWatcher(
        IReadOnlyList<string> directories,
        Func<string?, bool> isCanary,
        RansomwareBurstDetector? detector = null,
        Func<DateTimeOffset>? clock = null,
        Func<string?, bool>? looksEncrypted = null)
    {
        _directories = directories ?? throw new ArgumentNullException(nameof(directories));
        _isCanary = isCanary ?? throw new ArgumentNullException(nameof(isCanary));
        _detector = detector ?? new RansomwareBurstDetector();
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _looksEncrypted = looksEncrypted ?? RansomwareEntropySampler.LooksEncrypted;
    }

    /// <summary>The burst detector, exposed so the operator can acknowledge (Reset) after responding.</summary>
    public RansomwareBurstDetector Detector => _detector;

    /// <summary>How many directories are actively watched. Zero until <see cref="Start"/>.</summary>
    public int WatchedDirectoryCount
    {
        get { lock (_gate) { return _watchers.Count; } }
    }

    /// <summary>
    /// Times Windows reported that it dropped changes because the watch buffer overran. Non-zero
    /// means the detector was blind for an interval, which is a coverage gap the operator must see
    /// rather than a quiet zero in the count.
    /// </summary>
    public int OverflowCount => Volatile.Read(ref _overflows);

    /// <summary>Changes discarded because the internal queue was full. Same reasoning as above.</summary>
    public int DroppedChangeCount => Volatile.Read(ref _dropped);

    /// <summary>True when any observation was lost, from either cause.</summary>
    public bool CoverageIsIncomplete => OverflowCount > 0 || DroppedChangeCount > 0;

    public void Start()
    {
        lock (_gate)
        {
            if (_started || _disposed)
            {
                return;
            }
            _started = true;

            foreach (var directory in _directories)
            {
                var watcher = TryCreate(directory);
                if (watcher is not null)
                {
                    _watchers.Add(watcher);
                }
            }

            // A dedicated thread rather than the pool: this one blocks on a queue for the lifetime
            // of the watch, and the codebase already pays for a starved pool once (a release build
            // failed on 2026-07-27 for exactly that reason).
            _worker = new Thread(DrainPending)
            {
                IsBackground = true,
                Name = "WinSight ransomware watcher",
            };
            _worker.Start();

            // Enable only after every watcher is registered, so no event can fire while Start is
            // still mutating _watchers.
            foreach (var watcher in _watchers)
            {
                watcher.EnableRaisingEvents = true;
            }
        }
    }

    private FileSystemWatcher? TryCreate(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            return null;
        }
        try
        {
            var watcher = new FileSystemWatcher(directory)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.DirectoryName,
                InternalBufferSize = WatchBufferBytes,
            };
            watcher.Created += OnChanged;
            watcher.Changed += OnChanged;
            watcher.Deleted += OnChanged;
            watcher.Renamed += OnChanged;
            watcher.Error += OnError;
            // Deliberately NOT enabled here; Start enables them all once registration is complete.
            return watcher;
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            return null;
        }
    }

    /// <summary>
    /// Windows raises this when it discarded changes. Counting it is the whole point: an
    /// unhandled Error event on a <see cref="FileSystemWatcher"/> means lost observations that
    /// nothing ever notices.
    /// </summary>
    private void OnError(object sender, ErrorEventArgs e)
    {
        Interlocked.Increment(ref _overflows);

        // The watch itself is torn down by an internal buffer overflow, so re-arm it. Without this
        // the first burst would end monitoring of that directory permanently, which is the opposite
        // of what a detector should do when it sees a burst.
        if (sender is FileSystemWatcher watcher)
        {
            try
            {
                watcher.EnableRaisingEvents = false;
                watcher.EnableRaisingEvents = true;
            }
            catch (Exception ex) when (ex is IOException
                                         or ObjectDisposedException
                                         or UnauthorizedAccessException
                                         or System.Security.SecurityException)
            {
                // The directory is gone or the watcher is disposed; the overflow count already
                // records that coverage is incomplete.
            }
        }
    }

    /// <summary>
    /// Runs on the thread Windows delivers change notifications on, so it does no I/O, takes no
    /// lock a consumer could hold, and raises no event. It captures and returns.
    /// </summary>
    private void OnChanged(object sender, FileSystemEventArgs e)
    {
        // A rename reports the decoy as the OLD path, so that is what identifies a touched canary.
        var identity = e is RenamedEventArgs renamed ? renamed.OldFullPath : e.FullPath;
        try
        {
            if (!_pending.TryAdd(new PendingChange(e.ChangeType, identity, e.FullPath)))
            {
                Interlocked.Increment(ref _dropped);
            }
        }
        catch (Exception ex) when (ex is ObjectDisposedException or InvalidOperationException)
        {
            // Windows delivers this on a thread pool thread, and an unhandled exception there ends
            // the process. Disposal completes the queue and then disposes it after a bounded join,
            // so a callback still in flight when that join expires - a slow consumer, an entropy
            // read on a network file - would arrive at a disposed collection and take the dashboard
            // down during an ordinary shutdown. The change is already lost at that point; losing it
            // quietly is the correct outcome, and the count below is deliberately not incremented
            // because the watch is ending rather than falling behind.
        }
    }

    private void DrainPending()
    {
        try
        {
            foreach (var change in _pending.GetConsumingEnumerable())
            {
                Process(change);
            }
        }
        catch (Exception ex) when (ex is ObjectDisposedException or InvalidOperationException)
        {
            // The queue was completed and disposed during shutdown.
        }
    }

    private void Process(PendingChange change)
    {
        try
        {
            var isCanary = _isCanary(change.IdentityPath);

            // Only score content for a create/change of an ordinary file; the sampler's own
            // extension gate then skips formats that are compressed by design.
            var looksEncrypted = !isCanary
                && change.ChangeType is WatcherChangeTypes.Created or WatcherChangeTypes.Changed
                && _looksEncrypted(change.FullPath);

            var kind = RansomwareSignalClassifier.Classify(change.ChangeType, isCanary, looksEncrypted);
            if (kind is null)
            {
                return;
            }

            // The path is passed so the detector counts distinct files: Windows reports several
            // change notifications for one file being written, and counting raw events made a single
            // large save look like a burst.
            if (_detector.Observe(kind.Value, _clock(), change.IdentityPath))
            {
                Detected?.Invoke(this, new RansomwareDetectedEventArgs(kind.Value, change.FullPath));
            }
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            // One unreadable file must not end the watch. The next change is still processed.
        }
    }

    public void Dispose()
    {
        // Snapshot under the lock: Start may still be adding watchers on another thread.
        FileSystemWatcher[] watchers;
        Thread? worker;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            watchers = [.. _watchers];
            worker = _worker;
            _worker = null;
        }
        foreach (var watcher in watchers)
        {
            watcher.EnableRaisingEvents = false;
            watcher.Created -= OnChanged;
            watcher.Changed -= OnChanged;
            watcher.Deleted -= OnChanged;
            watcher.Renamed -= OnChanged;
            watcher.Error -= OnError;
            watcher.Dispose();
        }

        _pending.CompleteAdding();
        // Bounded: a consumer whose handler hangs must not hold up disposal of the dashboard.
        worker?.Join(TimeSpan.FromSeconds(2));
        _pending.Dispose();
    }

    /// <param name="IdentityPath">The path that decides whether this is a decoy (old path on rename).</param>
    /// <param name="FullPath">The path reported to the operator.</param>
    private readonly record struct PendingChange(
        WatcherChangeTypes ChangeType,
        string IdentityPath,
        string FullPath);
}
