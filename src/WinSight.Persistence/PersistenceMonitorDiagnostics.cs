using WinSight.Core;

namespace WinSight.Persistence;

/// <summary>Raised when a genuinely new persistence entry has been surfaced.</summary>
public sealed class PersistenceDetectedEventArgs(PersistenceEvent detected) : EventArgs
{
    public PersistenceEvent Detected { get; } = detected;
}

/// <summary>Raised when entries were baselined because WinSight could read their location for the first time.</summary>
public sealed class PersistenceCoverageGainEventArgs(PersistenceCoverageGain gain) : EventArgs
{
    public PersistenceCoverageGain Gain { get; } = gain;
}

/// <summary>The monitor operation that failed.</summary>
public enum PersistenceMonitorOperation
{
    Scan,
    Notification,
    BaselineSave,
    SourceShutdown,

    /// <summary>The change source could not be armed, so live monitoring never started.</summary>
    WatcherArming,
}

/// <summary>One contained failure, kept whole so it can be diagnosed.</summary>
public sealed record PersistenceMonitorFault(
    PersistenceMonitorOperation Operation,
    Exception Exception,
    DateTimeOffset AtUtc);

/// <summary>
/// What the monitor could not do. Nothing here is silent: a failed scan, save or notification is
/// counted, the last one is kept whole, and undelivered arrivals stay visible until delivered.
/// </summary>
public sealed record PersistenceMonitorDiagnostics(
    int PendingNotifications,
    int ScanFailures,
    int NotificationFailures,
    int SaveFailures,
    bool RetryScheduled,
    bool AutomaticRetriesExhausted,
    bool ShutdownDeferred,
    PersistenceMonitorFault? LastFault)
{
    /// <summary>True when an arrival is undelivered or the last scan or save has not recovered.</summary>
    public bool IsDegraded { get; init; }

    /// <summary>
    /// Arrivals reported but not kept in the bounded display list because it was full. They were
    /// notified; only the in-app list is incomplete.
    /// </summary>
    public int UnlistedArrivals { get; init; }

    /// <summary>OS watcher loss/error signals observed since this monitor started.</summary>
    public int SourceLostObservations { get; init; }

    /// <summary>Change-source notifications a subscriber failed to handle.</summary>
    public int SourceNotificationFailures { get; init; }

    /// <summary>Whether an operator-triggered retry can still make progress.</summary>
    public bool RetryableFailurePending { get; init; }

    /// <summary>
    /// Entries baselined without an alert since this monitor started, because their location was
    /// read in full for the first time. When they appeared is unknown (RA-03).
    /// </summary>
    public int CoverageGainEntries { get; init; }

    /// <summary>Coverage-gain notices not yet accepted by every subscriber.</summary>
    public int PendingCoverageGains { get; init; }

    /// <summary>Provider-neutral source lifecycle, loss and recovery counters when available.</summary>
    public SensorHealthSnapshot? SourceHealth { get; init; }
}
