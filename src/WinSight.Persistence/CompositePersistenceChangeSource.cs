using WinSight.Core;

namespace WinSight.Persistence;

/// <summary>
/// Fans several <see cref="IPersistenceChangeSource"/>s into one, so a single
/// <see cref="PersistenceMonitor"/> can watch the registry and the filesystem together. It forwards
/// every child's <see cref="SurfaceChanged"/>, starts and disposes them all, and owns nothing else.
/// </summary>
public sealed class CompositePersistenceChangeSource :
    IPersistenceChangeSource, IPersistenceWatchCoverage, IPersistenceWatchDiagnostics
{
    private readonly IReadOnlyList<IPersistenceChangeSource> _sources;
    private readonly Lock _gate = new();
    private bool _started;
    private bool _disposed;

    public event EventHandler<PersistenceSurfaceChangedEventArgs>? SurfaceChanged;

    /// <inheritdoc />
    /// <remarks>
    /// The sum over the sources that can report it. A source that cannot say how much it watches
    /// contributes nothing to either number rather than a zero to one of them, which would read as
    /// a gap it has no evidence for.
    /// </remarks>
    public int RequestedLocations =>
        _sources.OfType<IPersistenceWatchCoverage>().Sum(source => source.RequestedLocations);

    /// <inheritdoc />
    public int ArmedLocations =>
        _sources.OfType<IPersistenceWatchCoverage>().Sum(source => source.ArmedLocations);

    /// <inheritdoc />
    public int LostObservationCount =>
        _sources.OfType<IPersistenceWatchDiagnostics>().Sum(source => source.LostObservationCount);

    /// <inheritdoc />
    public int NotificationFailures =>
        _sources.OfType<IPersistenceWatchDiagnostics>().Sum(source => source.NotificationFailures);

    /// <inheritdoc />
    public SensorHealthSnapshot SensorHealth
    {
        get
        {
            var snapshots = _sources
                .OfType<ISensorHealthSource>()
                .Select(source => source.SensorHealth)
                .ToArray();
            var requested = snapshots.Sum(snapshot => snapshot.RequestedSources);
            var active = snapshots.Sum(snapshot => snapshot.ActiveSources);
            var lifecycle = snapshots.Length == 0
                ? SensorLifecycle.NotStarted
                : snapshots.Any(snapshot => snapshot.Lifecycle == SensorLifecycle.Running)
                    ? SensorLifecycle.Running
                    : snapshots.All(snapshot => snapshot.Lifecycle == SensorLifecycle.NotStarted)
                        ? SensorLifecycle.NotStarted
                        : snapshots.All(snapshot => snapshot.Lifecycle == SensorLifecycle.Stopped)
                            ? SensorLifecycle.Stopped
                            : SensorLifecycle.Failed;
            return new SensorHealthSnapshot(
                "Persistence",
                lifecycle,
                requested,
                active,
                snapshots.Sum(snapshot => snapshot.ObservedEvents),
                snapshots.Sum(snapshot => snapshot.LostEvents),
                snapshots.Sum(snapshot => snapshot.RecoveryAttempts),
                snapshots.Sum(snapshot => snapshot.SuccessfulRecoveries),
                snapshots.Sum(snapshot => snapshot.DeliveryFailures),
                snapshots.FirstOrDefault(snapshot => snapshot.FailureCode is not null).FailureCode);
        }
    }

    public CompositePersistenceChangeSource(params IPersistenceChangeSource[] sources)
        : this((IEnumerable<IPersistenceChangeSource>)sources)
    {
    }

    public CompositePersistenceChangeSource(IEnumerable<IPersistenceChangeSource> sources)
    {
        ArgumentNullException.ThrowIfNull(sources);
        _sources = sources.ToArray();
        foreach (var source in _sources)
        {
            source.SurfaceChanged += Forward;
        }
    }

    /// <summary>The default autostart change source: registry + filesystem watchers over the enumerators.</summary>
    public static CompositePersistenceChangeSource ForEnumerators(IEnumerable<IAutostartEnumerator> enumerators)
    {
        ArgumentNullException.ThrowIfNull(enumerators);
        var list = enumerators as IReadOnlyList<IAutostartEnumerator> ?? enumerators.ToArray();
        return new CompositePersistenceChangeSource(
            RegistryChangeWatcher.FromEnumerators(list),
            FileSystemPersistenceWatcher.FromEnumerators(list));
    }

    private void Forward(object? sender, PersistenceSurfaceChangedEventArgs e) =>
        SurfaceChanged?.Invoke(this, e);

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
        foreach (var source in _sources)
        {
            source.Start();
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
        foreach (var source in _sources)
        {
            source.SurfaceChanged -= Forward;
            source.Dispose();
        }
    }
}
