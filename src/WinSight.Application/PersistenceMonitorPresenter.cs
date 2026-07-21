using WinSight.Attribution;
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
    /// <param name="detections">The arrivals to render.</param>
    /// <param name="droppedChanges">Arrivals the log could not record, named in the summary.</param>
    /// <param name="attribute">
    /// Optional lookup of the write that installed an entry, shaped like
    /// <see cref="AttributionHost.Attribute"/>. Null — the default — renders exactly as before, so
    /// attribution stays an enrichment: a detection is never withheld because nobody could name its
    /// author, and a name is never invented when the lookup has none.
    /// </param>
    public static ToolReport BuildReport(
        IReadOnlyList<PersistenceEvent> detections,
        int droppedChanges,
        Func<string?, DateTimeOffset, WriteObservation?>? attribute = null)
    {
        ArgumentNullException.ThrowIfNull(detections);

        var builder = new ToolReport.Builder("persistence-live");
        foreach (var detection in detections)
        {
            var entry = detection.Entry;
            var displayedPath = entry.ImagePath ?? entry.ExpectedImagePath ?? entry.Command;
            // The write is looked up at first sight, not now: a detection surfaced minutes later
            // would otherwise fall outside the index's window and lose an author it did have.
            var author = attribute?.Invoke(entry.Location, detection.FirstSeenUtc);
            builder.Add(
                detection.IsNotable ? Severity.Notable : Severity.Info,
                $"{entry.Vector}/{entry.Name}",
                author is null
                    ? $"{displayedPath}  [{StatusLabel(entry.Status)}]"
                    : $"{displayedPath}  [{StatusLabel(entry.Status)}]  ← written by {Path.GetFileName(author.ExecutablePath)} (pid {author.ProcessId})",
                new Dictionary<string, string?>
                {
                    ["writtenBy"] = author?.ExecutablePath,
                    ["writtenByPid"] = author?.ProcessId.ToString(),
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
    /// The journal line for a detection: what arrived, where it points, and — when attribution was
    /// watching and can say — which program put it there.
    /// </summary>
    /// <remarks>
    /// Lives here rather than in the dashboard because it is the one sentence an operator reads when
    /// they come back to a machine that alerted while they were away, and a sentence that important
    /// should be pinned by tests instead of assembled inline in a WPF event handler.
    ///
    /// The journal records the full executable path, not just the file name shown in the balloon: it
    /// is opened deliberately, on one's own machine, precisely because one needs to know exactly
    /// which program to look at.
    /// </remarks>
    public static string AlertDetail(
        PersistenceEvent detection,
        Func<string?, DateTimeOffset, WriteObservation?>? attribute = null)
    {
        ArgumentNullException.ThrowIfNull(detection);
        var entry = detection.Entry;
        var target = entry.ImagePath ?? entry.ExpectedImagePath ?? entry.Command;
        var author = attribute?.Invoke(entry.Location, detection.FirstSeenUtc);
        return author is null
            ? $"{entry.Name} — {target}"
            : $"{entry.Name} — {target} — written by {author.ExecutablePath} (pid {author.ProcessId})";
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
