using WinSight.Core;

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
/// <summary>
/// What a change source was asked to watch versus what it actually armed.
/// </summary>
/// <remarks>
/// Real-time monitoring fails quietly by design: a key that will not open, a directory that is not
/// there, a watch Windows refuses. Every one of those leaves the monitor running and blind in that
/// one place, and without a count the dashboard shows a monitor that is on and says nothing about
/// what it can see. Optional, so a source with nothing to report is not forced to invent a number.
/// </remarks>
public interface IPersistenceWatchCoverage
{
    /// <summary>Locations this source was asked to watch.</summary>
    int RequestedLocations { get; }

    /// <summary>Locations it actually opened. Zero before Start.</summary>
    int ArmedLocations { get; }
}

/// <summary>
/// Cumulative evidence that a live source lost OS observations or could not deliver a change
/// notification. Optional, so sources that cannot measure either do not invent healthy zeroes.
/// </summary>
public interface IPersistenceWatchDiagnostics : ISensorHealthSource
{
    /// <summary>OS loss/error signals after which one or more changes may have been missed.</summary>
    int LostObservationCount { get; }

    /// <summary>Change notifications rejected by a subscriber.</summary>
    int NotificationFailures { get; }

    /// <summary>
    /// Compatibility fallback for external/simple sources that expose the legacy counters only.
    /// First-party watchers override it with their complete lifecycle and recovery snapshot.
    /// </summary>
    SensorHealthSnapshot ISensorHealthSource.SensorHealth => new(
        "Persistence source",
        SensorLifecycle.NotStarted,
        RequestedSources: 0,
        ActiveSources: 0,
        ObservedEvents: 0,
        LostEvents: LostObservationCount,
        RecoveryAttempts: 0,
        SuccessfulRecoveries: 0,
        DeliveryFailures: NotificationFailures);
}

public interface IPersistenceChangeSource : IDisposable
{
    event EventHandler<PersistenceSurfaceChangedEventArgs>? SurfaceChanged;

    /// <summary>Begins delivering change notifications. Idempotent; safe to call once.</summary>
    void Start();
}
