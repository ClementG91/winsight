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
/// <see cref="Detected"/> once per burst (or immediately on a touched canary). Thin I/O layer — its
/// runtime is validated on a real machine; the decisions live in the tested classifier and detector.
/// </summary>
public sealed class RansomwareFileWatcher : IDisposable
{
    private readonly IReadOnlyList<string> _directories;
    private readonly Func<string?, bool> _isCanary;
    private readonly RansomwareBurstDetector _detector;
    private readonly Func<DateTimeOffset> _clock;
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly Lock _gate = new();
    private bool _started;
    private bool _disposed;

    public event EventHandler<RansomwareDetectedEventArgs>? Detected;

    public RansomwareFileWatcher(
        IReadOnlyList<string> directories,
        Func<string?, bool> isCanary,
        RansomwareBurstDetector? detector = null,
        Func<DateTimeOffset>? clock = null)
    {
        _directories = directories ?? throw new ArgumentNullException(nameof(directories));
        _isCanary = isCanary ?? throw new ArgumentNullException(nameof(isCanary));
        _detector = detector ?? new RansomwareBurstDetector();
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>The burst detector, exposed so the operator can acknowledge (Reset) after responding.</summary>
    public RansomwareBurstDetector Detector => _detector;

    /// <summary>How many directories are actively watched. Zero until <see cref="Start"/>.</summary>
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

            foreach (var directory in _directories)
            {
                var watcher = TryCreate(directory);
                if (watcher is not null)
                {
                    _watchers.Add(watcher);
                }
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
        // A rename of a canary reports the decoy as the OLD path, so check that for renames.
        var isCanary = e is RenamedEventArgs renamed
            ? _isCanary(renamed.OldFullPath)
            : _isCanary(e.FullPath);

        var kind = RansomwareSignalClassifier.Classify(e.ChangeType, isCanary);
        if (kind is null)
        {
            return;
        }

        if (_detector.Observe(kind.Value, _clock()))
        {
            Detected?.Invoke(this, new RansomwareDetectedEventArgs(kind.Value, e.FullPath));
        }
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
