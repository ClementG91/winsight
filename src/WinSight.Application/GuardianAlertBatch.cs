using WinSight.Persistence;

namespace WinSight.Application;

/// <summary>
/// How a group of near-simultaneous Guardian detections should be announced: as one detection, or as
/// a count.
/// </summary>
/// <param name="Count">Detections in the batch.</param>
/// <param name="NotableCount">How many of them are notable.</param>
/// <param name="Single">The detection to describe, when the batch holds exactly one.</param>
public readonly record struct GuardianAlertBatch(
    int Count,
    int NotableCount,
    PersistenceEvent? Single)
{
    /// <summary>True when the operator should be shown one entry rather than a total.</summary>
    public bool IsSingle => Count == 1 && Single is not null;

    /// <summary>True when anything in the batch is worth an alarming icon.</summary>
    public bool IsNotable => NotableCount > 0;
}

/// <summary>
/// Groups Guardian detections that arrive together, so one act by the operator produces one alert.
/// </summary>
/// <remarks>
/// <b>Why this exists.</b> Guardian raised one tray balloon per new autostart entry, and an ordinary
/// software installation creates several at once - a service, a scheduled task, a Run key, a COM
/// registration. Six balloons in a few seconds for one thing the operator just did is not six times
/// the information; it is the mechanism by which somebody learns to dismiss WinSight's alerts
/// without reading them. Alert fatigue is a security failure, not a presentation one: the alert that
/// matters arrives in the same shape as the five that did not.
///
/// <b>What it deliberately does not do.</b> It never drops a detection - every one is still
/// journalled and still appears in the alerts view. It only decides how many balloons to raise, and
/// it never merges a notable arrival into silence: a batch containing anything notable is announced
/// as notable.
///
/// The pure decision lives here, without a timer, so the rule is testable. The window is the
/// caller's, because only the UI knows what "at the same time" should feel like.
/// </remarks>
public static class GuardianAlertBatcher
{
    /// <summary>
    /// How long to wait for more detections before announcing. Long enough to cover an installer
    /// writing several surfaces, short enough that a real alert is not delayed noticeably.
    /// </summary>
    public static readonly TimeSpan DefaultWindow = TimeSpan.FromSeconds(3);

    /// <summary>Describes what to announce for a set of detections that arrived together.</summary>
    public static GuardianAlertBatch Describe(IReadOnlyList<PersistenceEvent> detections)
    {
        ArgumentNullException.ThrowIfNull(detections);
        if (detections.Count == 0)
        {
            return new GuardianAlertBatch(0, 0, null);
        }

        var notable = detections.Count(detection => detection.IsNotable);
        return detections.Count == 1
            ? new GuardianAlertBatch(1, notable, detections[0])
            // The notable one leads when there is one, so a batch of six whose sixth is the
            // interesting one does not present the first as its representative.
            : new GuardianAlertBatch(
                detections.Count,
                notable,
                detections.FirstOrDefault(detection => detection.IsNotable) ?? detections[0]);
    }

    /// <summary>
    /// The localization key for a batch's balloon: the single-entry keys when there is one entry,
    /// and a counted form otherwise.
    /// </summary>
    public static string BalloonMessageKey(GuardianAlertBatch batch) =>
        batch.IsSingle
            ? PersistenceMonitorPresenter.BalloonMessageKey(batch.Single!)
            : batch.IsNotable
                ? "GuardianDetectedBatchNotable"
                : "GuardianDetectedBatchSigned";
}
