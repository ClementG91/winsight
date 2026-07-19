namespace WinSight.Persistence;

/// <summary>
/// Fans several <see cref="IPersistenceChangeSource"/>s into one, so a single
/// <see cref="PersistenceMonitor"/> can watch the registry and the filesystem together. It forwards
/// every child's <see cref="SurfaceChanged"/>, starts and disposes them all, and owns nothing else.
/// </summary>
public sealed class CompositePersistenceChangeSource : IPersistenceChangeSource
{
    private readonly IReadOnlyList<IPersistenceChangeSource> _sources;
    private readonly Lock _gate = new();
    private bool _started;
    private bool _disposed;

    public event EventHandler<PersistenceSurfaceChangedEventArgs>? SurfaceChanged;

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
