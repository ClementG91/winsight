namespace WinSight.Ransomware;

/// <summary>
/// Wires canary planting to the file watcher and the burst detector: on start it plants decoys in the
/// protected directories and begins watching; on a touched canary or a rename/delete burst it raises
/// <see cref="Detected"/> once. On dispose it removes the decoys. User-mode — it watches the user's
/// own directories and needs no elevation. It detects and alerts; it never stops a process.
/// </summary>
public sealed class RansomwareMonitor : IDisposable
{
    private readonly IReadOnlyList<string> _directories;
    private readonly CanaryManager _canaries;
    private readonly string? _manifestPath;
    private readonly byte[]? _seed;
    private readonly RansomwareFileWatcher _watcher;
    private readonly Lock _gate = new();
    private bool _started;
    private bool _disposed;

    public event EventHandler<RansomwareDetectedEventArgs>? Detected;

    public RansomwareMonitor(
        IReadOnlyList<string>? directories = null,
        RansomwareBurstDetector? detector = null)
        : this(directories, detector, seed: null, manifestPath: null)
    {
    }

    /// <summary>Isolated decoy identity and manifest, so tests never touch the operator's state.</summary>
    internal RansomwareMonitor(
        IReadOnlyList<string>? directories,
        RansomwareBurstDetector? detector,
        byte[]? seed,
        string? manifestPath)
    {
        _seed = seed;
        _manifestPath = manifestPath;
        _canaries = new CanaryManager(seed, manifestPath);
        _directories = directories ?? CanaryManager.DefaultDirectories();
        _watcher = new RansomwareFileWatcher(
            _directories,
            _canaries.IsCanary,
            detector,
            // A decoy rewritten with its own bytes - a OneDrive placeholder hydrating, a sync
            // client round-tripping the file - is not a touch. Without this the one signal the
            // product presents as unambiguous was raised by ordinary cloud storage.
            canaryIsIntact: _canaries.ContentIsIntact);
        _watcher.Detected += OnWatcherDetected;
    }

    /// <summary>The planted decoys (empty until <see cref="Start"/>).</summary>
    public IReadOnlyList<string> Canaries => _canaries.Planted;

    /// <summary>The burst detector, for acknowledging (Reset) after the operator responds.</summary>
    public RansomwareBurstDetector Detector => _watcher.Detector;

    /// <summary>Directories actually being watched. Zero after a start that could not open any.</summary>
    public int WatchedDirectoryCount => _watcher.WatchedDirectoryCount;

    /// <summary>
    /// True when observations were lost - a kernel buffer overrun or a full queue. Surfaced so the
    /// operator sees a gap in coverage instead of a reassuring zero in the count.
    /// </summary>
    public bool CoverageIsIncomplete => _watcher.CoverageIsIncomplete || Volatile.Read(ref _notificationFailures) > 0;

    /// <summary>Directories this monitor was asked to protect.</summary>
    public int RequestedDirectoryCount => _directories.Count;

    /// <summary>
    /// Directories that are both watched right now and hold their full set of decoys planted by this
    /// session.
    /// </summary>
    /// <remarks>
    /// <see cref="WatchedDirectoryCount"/> alone read as full protection when preserved files from an
    /// earlier run occupied every decoy name: the watch was live but no decoy existed to be touched.
    /// Cleanup deliberately preserves such files, so the honest fix is to count what is armed.
    /// </remarks>
    public int ArmedDirectoryCount => _directories.Count(directory =>
        _watcher.IsWatching(directory) && _canaries.PlantedCount(directory) == CanaryIdentity.PerDirectory);

    /// <summary>Plants the decoys, then starts watching. Idempotent.</summary>
    public void Start()
    {
        lock (_gate)
        {
            if (_started || _disposed)
            {
                return;
            }
            _started = true;
        }
        // Sweep decoys a previous run left behind (crash/kill) before planting fresh ones, so the
        // user's folders never accumulate hidden files.
        CanaryManager.RemoveOrphans(_directories, _manifestPath, _seed);
        _canaries.Plant(_directories);
        _watcher.Start();
    }

    /// <summary>Detections a subscriber of this monitor failed to handle.</summary>
    public int NotificationFailures => Volatile.Read(ref _notificationFailures) + _watcher.NotificationFailures;

    private int _notificationFailures;

    private void OnWatcherDetected(object? sender, RansomwareDetectedEventArgs e)
    {
        try
        {
            foreach (var handler in Detected?.GetInvocationList() ?? [])
            {
                try
                {
                    ((EventHandler<RansomwareDetectedEventArgs>)handler)(this, e);
                }
                catch (Exception ex) when (!RansomwareFileWatcher.IsCatastrophic(ex))
                {
                    // One faulty consumer must not keep the others from the alert.
                    Interlocked.Increment(ref _notificationFailures);
                }
            }
        }
        finally
        {
            // The detector fires once per burst by design (so a single burst is one alert, not one per
            // file). Without re-arming here, the FIRST alert of the whole session would be the ONLY one
            // ever raised. Re-armed in finally: a failing subscriber used to skip this and latch it.
            _watcher.Detector.Reset();
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
        _watcher.Detected -= OnWatcherDetected;
        _watcher.Dispose();
        _canaries.Remove();
    }
}
