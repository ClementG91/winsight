using System.Collections.Concurrent;

using WinSight.Core;

namespace WinSight.Persistence;

/// <summary>
/// A filesystem-backed <see cref="IPersistenceChangeSource"/>: it raises <see cref="SurfaceChanged"/>
/// when a file appears, changes, is renamed, or is removed under any watched directory (the Startup
/// folders and <c>\System32\Tasks</c>). Like the registry watcher it is a dumb trigger — the
/// enumerators re-read the truth. Thin I/O layer; the pure core holds all decisions.
/// </summary>
public sealed class FileSystemPersistenceWatcher : IPersistenceChangeSource, IPersistenceWatchCoverage
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

    private readonly IReadOnlyList<PersistenceWatchTarget> _targets;
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly Dictionary<FileSystemWatcher, PersistenceWatchTarget> _targetByWatcher = [];
    private readonly ConcurrentDictionary<FileSystemWatcher, byte> _lost = new();
    private readonly Lock _gate = new();
    private int _overflows;
    private bool _started;
    private bool _disposed;

    public event EventHandler<PersistenceSurfaceChangedEventArgs>? SurfaceChanged;

    public FileSystemPersistenceWatcher(IEnumerable<PersistenceWatchTarget> targets)
    {
        ArgumentNullException.ThrowIfNull(targets);
        _targets = FileSystemTargets(targets);
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

    /// <summary>Watches that overflowed and could not be re-armed, so they are no longer observing.</summary>
    public int LostWatchCount => _lost.Count;

    /// <inheritdoc />
    /// <remarks>
    /// A watch torn down by an overflow and not recoverable is not armed, whatever the list length
    /// says. Counting it kept the difference between <see cref="RequestedLocations"/> and this
    /// number at zero while a Startup folder had stopped being observed - a coverage hole presented
    /// as coverage, which is the one thing these watchers promise never to do.
    /// </remarks>
    public int ArmedLocations => Math.Max(0, WatchedDirectoryCount - _lost.Count);

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

            // Only begin delivering events once EVERY watcher is registered. Enabling inside
            // TryCreate would let an event fire on a thread-pool thread while this loop is still
            // writing _targetByWatcher, and a Dictionary read racing a write can throw, return
            // garbage, or spin forever — silently killing the filesystem half of persistence
            // monitoring, which is the worst failure mode a security tool has.
            foreach (var watcher in _watchers)
            {
                watcher.EnableRaisingEvents = true;
            }
        }
    }

    private FileSystemWatcher? TryCreate(PersistenceWatchTarget target)
    {
        if (string.IsNullOrWhiteSpace(target.Path)
            || !AutomaticFileAccess.IsLocal(target.Path)
            || !Directory.Exists(target.Path))
        {
            // A folder that does not exist (e.g. no Common Startup on this SKU) is an honest gap,
            // not an error: the on-start diff still covers it if it later appears at scan time.
            return null;
        }
        try
        {
            var watcher = new FileSystemWatcher(target.Path)
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
        Interlocked.Increment(ref _overflows);
        if (sender is not FileSystemWatcher watcher)
        {
            return;
        }
        try
        {
            watcher.EnableRaisingEvents = false;
            watcher.EnableRaisingEvents = true;
            _lost.TryRemove(watcher, out _);
        }
        catch (Exception ex) when (ex is IOException
                                     or ObjectDisposedException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            // The directory is gone or the watcher is disposed. Either way it is not observing, and
            // ArmedLocations must say so rather than counting a dead watch.
            _lost.TryAdd(watcher, 0);
        }
    }

    private void OnChanged(object sender, FileSystemEventArgs e)
    {
        var changed = sender is FileSystemWatcher watcher && _targetByWatcher.TryGetValue(watcher, out var target)
            ? new[] { target }
            : Array.Empty<PersistenceWatchTarget>();
        SurfaceChanged?.Invoke(this, new PersistenceSurfaceChangedEventArgs(changed));
    }

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
            watchers = [.. _watchers];
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
    }
}
