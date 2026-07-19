using WinSight.Persistence;
using WinSight.Reporting;

namespace WinSight.Application;

/// <summary>
/// UI-agnostic mapping of live persistence detections (Guardian) to the shared report model and to
/// localization keys, so the dashboard's existing findings rendering and actions serve the live
/// view unchanged. It is the single place that knows the live-detection field schema — deliberately
/// the same shape as the on-demand scan in <see cref="Adapters"/> — kept out of WPF so it is
/// unit-tested without a UI.
/// </summary>
public static class PersistenceMonitorPresenter
{
    /// <summary>The report kind tag on a live-detection row, distinct from an on-demand scan row.</summary>
    public const string LiveKind = "persistence-live";

    /// <summary>Builds a report of the currently-surfaced live detections, in the order given.</summary>
    public static ToolReport BuildReport(IReadOnlyList<PersistenceEvent> detections, int droppedChanges)
    {
        ArgumentNullException.ThrowIfNull(detections);

        var builder = new ToolReport.Builder("persistence-live");
        foreach (var detection in detections)
        {
            var entry = detection.Entry;
            var displayedPath = entry.ImagePath ?? entry.ExpectedImagePath ?? entry.Command;
            builder.Add(
                detection.IsNotable ? Severity.Notable : Severity.Info,
                $"{entry.Vector}/{entry.Name}",
                $"{displayedPath}  [{StatusLabel(entry.Status)}]",
                new Dictionary<string, string?>
                {
                    ["kind"] = LiveKind,
                    ["vector"] = entry.Vector.ToString(),
                    ["name"] = entry.Name,
                    ["path"] = displayedPath,
                    ["location"] = entry.Location,
                    ["command"] = entry.Command,
                    ["image"] = entry.ImagePath,
                    ["expectedImage"] = entry.ExpectedImagePath,
                    ["fileStatus"] = entry.ImageStatus.ToString(),
                    ["signature"] = entry.ImageStatus == WinSight.Persistence.ImageResolutionStatus.Present
                        ? entry.Signature.State.ToString()
                        : null,
                    ["status"] = entry.Status.ToString(),
                    ["signer"] = entry.Signature.Signer,
                    ["firstSeen"] = detection.FirstSeenUtc.ToString("O"),
                    ["lastSeen"] = detection.LastSeenUtc.ToString("O"),
                    ["observations"] = detection.Observations.ToString(),
                });
        }

        return builder.Build(Summary(detections.Count, detections.Count(d => d.IsNotable), droppedChanges));
    }

    /// <summary>
    /// The localization key for the tray balloon shown when a new entry is detected. A notable
    /// arrival (unsigned / untrusted / missing) is loud; a signed-trusted arrival is calm.
    /// </summary>
    public static string BalloonMessageKey(PersistenceEvent detection)
    {
        ArgumentNullException.ThrowIfNull(detection);
        return detection.IsNotable ? "GuardianDetectedNotable" : "GuardianDetectedSigned";
    }

    /// <summary>
    /// A plain-language one-line summary (English, like the scan's report detail; the dashboard
    /// localizes chrome, not report bodies). Names the blind spot when the log dropped arrivals.
    /// </summary>
    public static string Summary(int total, int notable, int dropped) =>
        dropped > 0
            ? $"{total} new autostart item(s), {notable} flagged, {dropped} not recorded (log full)"
            : $"{total} new autostart item(s), {notable} flagged";

    private static string StatusLabel(PersistenceStatus status) => status switch
    {
        PersistenceStatus.FileMissing => "file missing, signature not checked",
        PersistenceStatus.SignatureValid => "signature valid",
        PersistenceStatus.Unsigned => "unsigned",
        PersistenceStatus.InvalidSignature => "invalid signature",
        PersistenceStatus.AccessDenied => "access denied, signature not checked",
        _ => "verification error",
    };
}
