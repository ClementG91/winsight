namespace WinSight.Persistence;

/// <summary>
/// Names the watch targets that fired. An empty list means "unknown — re-scan everything"; a
/// populated list lets the monitor re-scan only the enumerators that own those targets.
/// </summary>
public sealed class PersistenceSurfaceChangedEventArgs(IReadOnlyList<PersistenceWatchTarget> changedTargets)
    : EventArgs
{
    public IReadOnlyList<PersistenceWatchTarget> ChangedTargets { get; } =
        changedTargets ?? Array.Empty<PersistenceWatchTarget>();
}

/// <summary>
/// A real-time source of "a persistence surface may have changed" signals. It is deliberately dumb:
/// it reports that something changed (and which watch target), never what — the enumerators remain
/// the source of truth. Implementations wrap OS change notifications (registry, filesystem, ETW).
/// The monitor depends only on this interface, so tests drive it with a fake.
/// </summary>
public interface IPersistenceChangeSource : IDisposable
{
    event EventHandler<PersistenceSurfaceChangedEventArgs>? SurfaceChanged;

    /// <summary>Begins delivering change notifications. Idempotent; safe to call once.</summary>
    void Start();
}
