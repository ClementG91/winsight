namespace WinSight.Persistence;

/// <summary>
/// A filesystem-backed <see cref="IPersistenceChangeSource"/>: it raises <see cref="SurfaceChanged"/>
/// when a file appears, changes, is renamed, or is removed under any watched directory (the Startup
/// folders and <c>\System32\Tasks</c>). Like the registry watcher it is a dumb trigger — the
/// enumerators re-read the truth. Thin I/O layer; the pure core holds all decisions.
/// </summary>
public sealed class FileSystemPersistenceWatcher : IPersistenceChangeSource
{
    private readonly IReadOnlyList<PersistenceWatchTarget> _targets;
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly Dictionary<FileSystemWatcher, PersistenceWatchTarget> _targetByWatcher = [];
    private readonly Lock _gate = new();
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
        }
    }

    private FileSystemWatcher? TryCreate(PersistenceWatchTarget target)
    {
        if (string.IsNullOrWhiteSpace(target.Path) || !Directory.Exists(target.Path))
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
            };
            watcher.Created += OnChanged;
            watcher.Changed += OnChanged;
            watcher.Deleted += OnChanged;
            watcher.Renamed += OnChanged;
            watcher.EnableRaisingEvents = true;
            return watcher;
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            return null;
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
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
        }
        foreach (var watcher in _watchers)
        {
            watcher.EnableRaisingEvents = false;
            watcher.Created -= OnChanged;
            watcher.Changed -= OnChanged;
            watcher.Deleted -= OnChanged;
            watcher.Renamed -= OnChanged;
            watcher.Dispose();
        }
    }
}
