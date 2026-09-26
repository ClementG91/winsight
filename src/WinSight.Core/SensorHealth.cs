namespace WinSight.Core;

/// <summary>The lifecycle state of an operating-system observation source.</summary>
public enum SensorLifecycle
{
    /// <summary>The source has not been asked to start.</summary>
    NotStarted,

    /// <summary>The source is currently observing at least part of its requested scope.</summary>
    Running,

    /// <summary>The source stopped because its owner requested shutdown.</summary>
    Stopped,

    /// <summary>The source was asked to run but cannot currently observe anything.</summary>
    Failed,
}

/// <summary>
/// A bounded, provider-neutral account of what a live sensor is actually doing. Counters are
/// cumulative for the sensor instance: a recovered loss remains evidence that coverage had a hole.
/// </summary>
/// <param name="Name">Stable operator-facing sensor identifier.</param>
/// <param name="Lifecycle">Whether the source is not started, running, stopped or failed.</param>
/// <param name="RequestedSources">OS locations/providers the sensor was asked to observe.</param>
/// <param name="ActiveSources">Requested sources currently armed.</param>
/// <param name="ObservedEvents">OS observations accepted by the sensor.</param>
/// <param name="LostEvents">Events or loss signals reported by the OS.</param>
/// <param name="RecoveryAttempts">Attempts to re-arm or restart observation after a loss.</param>
/// <param name="SuccessfulRecoveries">Recovery attempts that restored observation.</param>
/// <param name="DeliveryFailures">Observations that could not be delivered to a subscriber.</param>
/// <param name="FailureCode">Optional stable redacted failure token; never native exception text.</param>
public readonly record struct SensorHealthSnapshot(
    string Name,
    SensorLifecycle Lifecycle,
    int RequestedSources,
    int ActiveSources,
    long ObservedEvents,
    long LostEvents,
    long RecoveryAttempts,
    long SuccessfulRecoveries,
    long DeliveryFailures,
    string? FailureCode = null)
{
    /// <summary>
    /// True when the sensor is meant to observe but has a current or historical coverage hole.
    /// A successful recovery does not erase events that were already lost.
    /// </summary>
    public bool CoverageIncomplete =>
        Lifecycle == SensorLifecycle.Failed
        || Lifecycle == SensorLifecycle.Running && ActiveSources < RequestedSources
        || LostEvents > 0
        || DeliveryFailures > 0;
}

/// <summary>Implemented by live observation sources that can report truthful health.</summary>
public interface ISensorHealthSource
{
    SensorHealthSnapshot SensorHealth { get; }
}
