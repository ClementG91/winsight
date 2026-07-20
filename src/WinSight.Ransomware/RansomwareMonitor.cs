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
    private readonly CanaryManager _canaries = new();
    private readonly RansomwareFileWatcher _watcher;
    private readonly Lock _gate = new();
    private bool _started;
    private bool _disposed;

    public event EventHandler<RansomwareDetectedEventArgs>? Detected;

    public RansomwareMonitor(
        IReadOnlyList<string>? directories = null,
        RansomwareBurstDetector? detector = null)
    {
        _directories = directories ?? CanaryManager.DefaultDirectories();
        _watcher = new RansomwareFileWatcher(_directories, _canaries.IsCanary, detector);
        _watcher.Detected += OnWatcherDetected;
    }

    /// <summary>The planted decoys (empty until <see cref="Start"/>).</summary>
    public IReadOnlyList<string> Canaries => _canaries.Planted;

    /// <summary>The burst detector, for acknowledging (Reset) after the operator responds.</summary>
    public RansomwareBurstDetector Detector => _watcher.Detector;

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
        CanaryManager.RemoveOrphans(_directories);
        _canaries.Plant(_directories);
        _watcher.Start();
    }

    private void OnWatcherDetected(object? sender, RansomwareDetectedEventArgs e)
    {
        Detected?.Invoke(this, e);
        // The detector fires once per burst by design (so a single burst is one alert, not one per
        // file). Without re-arming here, the FIRST alert of the whole session would be the ONLY one
        // ever raised — a second wave of encryption, or a burst the operator missed, would go
        // completely silent. Re-arm right after notifying, so the next burst/touch alerts again.
        _watcher.Detector.Reset();
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
