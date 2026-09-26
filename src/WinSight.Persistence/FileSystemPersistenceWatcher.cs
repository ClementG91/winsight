using System.Collections.Concurrent;

using WinSight.Core;

namespace WinSight.Persistence;

/// <summary>
/// A filesystem-backed <see cref="IPersistenceChangeSource"/>: it raises <see cref="SurfaceChanged"/>
/// when a file appears, changes, is renamed, or is removed under any watched directory (the Startup
/// folders and <c>\System32\Tasks</c>). Like the registry watcher it is a dumb trigger — the
/// enumerators re-read the truth. Thin I/O layer; the pure core holds all decisions.
/// </summary>
public sealed class FileSystemPersistenceWatcher :
    IPersistenceChangeSource, IPersistenceWatchCoverage, IPersistenceWatchDiagnostics
{
    /// <summary>
    /// Kernel buffer per watched directory. 64 KiB is the documented practical maximum: beyond it
    /// the buffer must come from non-paged pool and Windows can fail the watch outright.
    /// </summary>
    /// <remarks>
    /// It was the 8 KiB default, roughly 250 pending events. <c>\System32\Tasks</c> is watched
    /// recursively, so an ordinary burst of task churn - or a deliberate one - overruns it. The
    /// ransomware watcher was rebuilt around exactly this and raised its buffer; this watcher, which
    /// is what tells Guardian a file appeared in a Startup folder, was left on the default.
    /// </remarks>
    private const int WatchBufferBytes = 64 * 1024;
    private static readonly TimeSpan DefaultRecoveryInterval = TimeSpan.FromSeconds(30);

    private readonly IReadOnlyList<PersistenceWatchTarget> _targets;
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly ConcurrentDictionary<FileSystemWatcher, PersistenceWatchTarget> _targetByWatcher = [];
    private readonly ConcurrentDictionary<PersistenceWatchTarget, byte> _lost = new();
    private readonly Lock _gate = new();
    private readonly TimeSpan _recoveryInterval;
    private Timer? _recoveryTimer;
    private int _recoveryRunning;
    private int _overflows;
    private long _observedEvents;
    private long _recoveryAttempts;
    private long _successfulRecoveries;
    private bool _started;
    private bool _disposed;

    public event EventHandler<PersistenceSurfaceChangedEventArgs>? SurfaceChanged;

    public FileSystemPersistenceWatcher(IEnumerable<PersistenceWatchTarget> targets)
        : this(targets, DefaultRecoveryInterval)
    {
    }

    internal FileSystemPersistenceWatcher(
        IEnumerable<PersistenceWatchTarget> targets,
        TimeSpan recoveryInterval)
    {
        ArgumentNullException.ThrowIfNull(targets);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(recoveryInterval, TimeSpan.Zero);
        _targets = FileSystemTargets(targets);
        _recoveryInterval = recoveryInterval;
    }

    /// <summary>The filesystem targets exposed by the given enumerators, flattened and de-duplicated.</summary>
    public static FileSystemPersistenceWatcher FromEnumerators(IEnumerable<IAutostartEnumerator> enumerators)
    {
        ArgumentNullException.ThrowIfNull(enumerators);
        return new FileSystemPersistenceWatcher(enumerators.SelectMany(e => e.WatchTargets));
    }

    /// <summary>Keeps only filesystem targets, de-duplicating identical path/recursive tuples.</summary>
    public static IReadOnlyList<PersistenceWatchTarget> FileSystemTargets(
        IEnumerable<PersistenceWatchTarget> targets) =>
        targets
            .Where(t => t.Kind == PersistenceWatchKind.FileSystem)
            .DistinctBy(t => (t.Path.ToLowerInvariant(), t.Recursive))
            .ToArray();

    /// <summary>How many directories were successfully attached. Zero until <see cref="Start"/>.</summary>
    public int WatchedDirectoryCount
    {
        get { lock (_gate) { return _watchers.Count; } }
    }

    /// <inheritdoc />
    public int RequestedLocations => _targets.Count;

    /// <summary>
    /// Times Windows reported that it discarded changes because the watch buffer overran. Non-zero
    /// means this watcher was blind for an interval.
    /// </summary>
    public int OverflowCount => Volatile.Read(ref _overflows);

    /// <inheritdoc />
    public int LostObservationCount => OverflowCount;

    /// <summary>Watches that overflowed and could not be re-armed, so they are no longer observing.</summary>
    public int LostWatchCount => _lost.Count;

    /// <inheritdoc />
    /// <remarks>
    /// A watch torn down by an overflow and not recoverable is not armed, whatever the list length
    /// says. Counting it kept the difference between <see cref="RequestedLocations"/> and this
    /// number at zero while a Startup folder had stopped being observed - a coverage hole presented
    /// as coverage, which is the one thing these watchers promise never to do.
    /// </remarks>
    public int ArmedLocations
    {
        get { lock (_gate) { return ActiveWatcherCountLocked(); } }
    }

    private int ActiveWatcherCountLocked() => _watchers.Count(watcher =>
        _targetByWatcher.TryGetValue(watcher, out var target) && !_lost.ContainsKey(target));

    /// <inheritdoc />
    public SensorHealthSnapshot SensorHealth
    {
        get
        {
            lock (_gate)
            {
                var active = ActiveWatcherCountLocked();
                var lifecycle = !_started
                    ? SensorLifecycle.NotStarted
                    : _disposed
                        ? SensorLifecycle.Stopped
                        : _targets.Count > 0 && active == 0
                            ? SensorLifecycle.Failed
                            : SensorLifecycle.Running;
                return new SensorHealthSnapshot(
                    "Persistence files",
                    lifecycle,
                    _targets.Count,
                    active,
                    Interlocked.Read(ref _observedEvents),
                    Volatile.Read(ref _overflows),
                    Interlocked.Read(ref _recoveryAttempts),
                    Interlocked.Read(ref _successfulRecoveries),
                    Volatile.Read(ref _notificationFailures));
            }
        }
    }

    public void Start()
    {
        lock (_gate)
        {
            if (_started || _disposed)
            {
                return;
            }
            _started = true;

            foreach (var target in _targets)
            {
                var watcher = TryCreate(target);
                if (watcher is not null)
                {
                    _watchers.Add(watcher);
                    _targetByWatcher[watcher] = target;
                }
            }

            // Only begin delivering events once every initial watcher is registered. Recovery can
            // add mappings later, so the map itself is concurrent; registration still happens
            // before enabling so a first event always carries its target.
            foreach (var watcher in _watchers.ToArray())
            {
                if (!TryEnable(watcher))
                {
                    _watchers.Remove(watcher);
                    _targetByWatcher.TryRemove(watcher, out _);
                    watcher.Dispose();
                }
            }
            if (ActiveWatcherCountLocked() < _targets.Count)
            {
                EnsureRecoveryTimerLocked();
            }
        }
    }

    private void EnsureRecoveryTimerLocked()
    {
        if (_disposed)
        {
            return;
        }
        if (_recoveryTimer is null)
        {
            _recoveryTimer = new Timer(
                _ => RetryUnavailable(),
                null,
                _recoveryInterval,
                _recoveryInterval);
        }
        else
        {
            _recoveryTimer.Change(_recoveryInterval, _recoveryInterval);
        }
    }

    /// <summary>
    /// Arms one watch. False for a folder that exists but this user may not watch.
    /// </summary>
    /// <remarks>
    /// <c>Directory.Exists</c> is true for <c>C:\Windows\System32\Tasks</c> without elevation, yet
    /// arming it throws. That exception used to escape <see cref="Start"/>, fail Guardian's whole
    /// start, and leave a standard user with no live persistence monitoring anywhere. One folder
    /// this user may not watch is a coverage gap, reported as such through
    /// <see cref="ArmedLocations"/>; the start-up reconciliation still covers it.
    /// </remarks>
    private static bool TryEnable(FileSystemWatcher watcher)
    {
        try
        {
            watcher.EnableRaisingEvents = true;
            return true;
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or ArgumentException)
        {
            return false;
        }
    }

    private FileSystemWatcher? TryCreate(PersistenceWatchTarget target)
    {
        using var lease = AutomaticFileAccess.TryAcquire(target.Path);
        if (lease is null || !lease.IsDirectory)
        {
            // A folder that does not exist (e.g. no Common Startup on this SKU) is an honest gap,
            // not an error: the on-start diff still covers it if it later appears at scan time.
            return null;
        }
        try
        {
            var watcher = new FileSystemWatcher(lease.FullPath)
            {
                IncludeSubdirectories = target.Recursive,
                NotifyFilter = NotifyFilters.FileName
                    | NotifyFilters.DirectoryName
                    | NotifyFilters.LastWrite
                    | NotifyFilters.CreationTime,
                InternalBufferSize = WatchBufferBytes,
            };
            watcher.Created += OnChanged;
            watcher.Changed += OnChanged;
            watcher.Deleted += OnChanged;
            watcher.Renamed += OnChanged;
            // Unhandled before. An internal-buffer overflow tears the watch down, and with no
            // handler the watcher stayed in the list, permanently deaf: Guardian stopped noticing
            // new Startup-folder files and nothing said so. The first burst ended monitoring of that
            // directory for the lifetime of the process, which is the opposite of what a detector
            // should do when it sees a burst.
            watcher.Error += OnError;
            if (!lease.IsCurrent())
            {
                watcher.Dispose();
                return null;
            }
            // Deliberately NOT enabled here — Start enables every watcher only after all of them are
            // registered, so no event can race the registration.
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
    /// Windows raises this when it discarded changes. The watch is torn down by the overflow, so
    /// re-arm it; when that fails the directory has stopped being observed and must stop counting
    /// as armed.
    /// </summary>
    private void OnError(object sender, ErrorEventArgs e)
    {
        if (sender is not FileSystemWatcher watcher)
        {
            CompleteLossRecovery(target: null, rearmed: false);
            return;
        }
        var rearmed = false;
        try
        {
            watcher.EnableRaisingEvents = false;
            watcher.EnableRaisingEvents = true;
            rearmed = true;
        }
        catch (Exception ex) when (ex is IOException
                                     or ObjectDisposedException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            // The directory is gone or the watcher is disposed. CompleteLossRecovery records that
            // it is not observing before forcing the reconciliation signal.
        }
        _targetByWatcher.TryGetValue(watcher, out var target);
        CompleteLossRecovery(target, rearmed);
    }

    /// <summary>
    /// Completes one OS loss/error path. Reconciliation is mandatory whether the watch re-armed or
    /// not: changes were discarded before this callback, so merely restarting would preserve the
    /// blind interval in Guardian's baseline.
    /// </summary>
    internal void CompleteLossRecovery(PersistenceWatchTarget? target, bool rearmed)
    {
        Interlocked.Increment(ref _overflows);
        Interlocked.Increment(ref _recoveryAttempts);
        if (rearmed)
        {
            Interlocked.Increment(ref _successfulRecoveries);
        }
        if (target is not null)
        {
            if (rearmed)
            {
                _lost.TryRemove(target, out _);
            }
            else
            {
                _lost.TryAdd(target, 0);
                lock (_gate)
                {
                    EnsureRecoveryTimerLocked();
                }
            }
        }
        NotifySurface(target is null ? [] : [target]);
    }

    /// <summary>
    /// Recreates watches that were unavailable at start or lost after an overflow. Recovery forces
    /// reconciliation because changes may have happened before the new watch became active.
    /// </summary>
    internal void RetryUnavailable()
    {
        if (Interlocked.Exchange(ref _recoveryRunning, 1) != 0)
        {
            return;
        }
        List<PersistenceWatchTarget> recovered = [];
        try
        {
            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }

                var active = _watchers
                    .Where(watcher => _targetByWatcher.TryGetValue(watcher, out var target)
                        && !_lost.ContainsKey(target))
                    .Select(watcher => _targetByWatcher[watcher])
                    .ToHashSet();
                foreach (var target in _targets.Where(target => !active.Contains(target)))
                {
                    Interlocked.Increment(ref _recoveryAttempts);
                    foreach (var stale in _watchers
                                 .Where(watcher => _targetByWatcher.TryGetValue(watcher, out var mapped)
                                     && mapped.Equals(target))
                                 .ToArray())
                    {
                        _watchers.Remove(stale);
                        _targetByWatcher.TryRemove(stale, out _);
                        DisposeWatcher(stale);
                    }

                    var replacement = TryCreate(target);
                    if (replacement is null)
                    {
                        continue;
                    }

                    _watchers.Add(replacement);
                    _targetByWatcher[replacement] = target;
                    if (!TryEnable(replacement))
                    {
                        _watchers.Remove(replacement);
                        _targetByWatcher.TryRemove(replacement, out _);
                        replacement.Dispose();
                        continue;
                    }
                    _lost.TryRemove(target, out _);
                    Interlocked.Increment(ref _successfulRecoveries);
                    recovered.Add(target);
                }

                if (ActiveWatcherCountLocked() == _targets.Count)
                {
                    _recoveryTimer?.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
                }
            }
        }
        finally
        {
            Volatile.Write(ref _recoveryRunning, 0);
        }

        foreach (var target in recovered)
        {
            NotifySurface([target]);
        }
    }

    private void OnChanged(object sender, FileSystemEventArgs e)
    {
        Interlocked.Increment(ref _observedEvents);
        var changed = sender is FileSystemWatcher watcher && _targetByWatcher.TryGetValue(watcher, out var target)
            ? new[] { target }
            : Array.Empty<PersistenceWatchTarget>();
        NotifySurface(changed);
    }

    private void NotifySurface(IReadOnlyList<PersistenceWatchTarget> changed)
    {
        try
        {
            SurfaceChanged?.Invoke(this, new PersistenceSurfaceChangedEventArgs(changed));
        }
        catch (Exception ex) when (!PersistenceMonitor.IsCatastrophic(ex))
        {
            // Raised on a thread-pool thread, where an escaping exception ends the process.
            Interlocked.Increment(ref _notificationFailures);
        }
    }

    private int _notificationFailures;

    /// <summary>Change notifications a subscriber failed to handle.</summary>
    public int NotificationFailures => Volatile.Read(ref _notificationFailures);

    public void Dispose()
    {
        // Snapshot under the lock: Start may still be adding watchers on another thread, and
        // iterating a List while it is mutated throws.
        FileSystemWatcher[] watchers;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            _recoveryTimer?.Dispose();
            _recoveryTimer = null;
            watchers = [.. _watchers];
        }
        foreach (var watcher in watchers)
        {
            DisposeWatcher(watcher);
        }
    }

    private void DisposeWatcher(FileSystemWatcher watcher)
    {
        watcher.EnableRaisingEvents = false;
        watcher.Created -= OnChanged;
        watcher.Changed -= OnChanged;
        watcher.Deleted -= OnChanged;
        watcher.Renamed -= OnChanged;
        watcher.Error -= OnError;
        watcher.Dispose();
    }
}
