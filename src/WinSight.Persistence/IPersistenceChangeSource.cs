namespace WinSight.Persistence;

/// <summary>
/// Names the surfaces a change notification implicates. An empty list means "unknown — re-scan
/// everything"; a populated list lets the monitor re-run only the affected enumerators.
/// </summary>
public sealed class PersistenceSurfaceChangedEventArgs(IReadOnlyList<AutostartVector> surfaces) : EventArgs
{
    public IReadOnlyList<AutostartVector> Surfaces { get; } = surfaces ?? Array.Empty<AutostartVector>();
}

/// <summary>
/// A real-time source of "a persistence surface may have changed" signals. It is deliberately dumb:
/// it reports that something changed, never what — the enumerators remain the source of truth.
/// Implementations wrap OS change notifications (registry, filesystem, ETW). The monitor depends
/// only on this interface, so tests drive it with a fake.
/// </summary>
public interface IPersistenceChangeSource : IDisposable
{
    event EventHandler<PersistenceSurfaceChangedEventArgs>? SurfaceChanged;

    /// <summary>Begins delivering change notifications. Idempotent; safe to call once.</summary>
    void Start();
}
