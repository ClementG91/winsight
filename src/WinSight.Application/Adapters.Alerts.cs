using WinSight.Reporting;

namespace WinSight.Application;

public static partial class Adapters
{
    /// <summary>
    /// The recorded history of real-time detections, read back from <see cref="AlertJournal"/>.
    /// </summary>
    /// <remarks>
    /// This is the one "tool" that inspects WinSight's own record rather than the machine: it is
    /// how an operator sees an alert they were not at the screen for. Windows can suppress a tray
    /// balloon outright (Focus Assist) or throttle it, so the balloon alone is not a record —
    /// this is. Every entry is <see cref="Severity.Notable"/> because everything in the journal is,
    /// by definition, something WinSight considered worth interrupting the operator for; the
    /// flagged-only filter therefore does not hide anything here.
    /// </remarks>
    public static ToolReport Alerts(int max = 200) => Alerts(AlertJournal.DefaultPath, max);

    /// <summary>
    /// Composes the report from a named journal. Internal so tests exercise the real composition
    /// against a fixture journal rather than whatever the machine running them happens to have
    /// recorded — and so they never write into the operator's own journal to get a fixture.
    /// </summary>
    internal static ToolReport Alerts(string journalPath, int max)
    {
        var journal = AlertJournal.ReadWithCoverage(journalPath, max);
        var alerts = journal.Entries;
        var b = new ToolReport.Builder("alerts");
        if (journal.Unreadable || journal.MalformedEntries > 0)
        {
            b.Add(
                Severity.Notable,
                "alert journal coverage incomplete",
                journal.Unreadable
                    ? "the local alert journal could not be read"
                    : $"{journal.MalformedEntries} malformed journal line(s) were ignored",
                new Dictionary<string, string?>
                {
                    ["kind"] = "acquisitionCoverage",
                    ["unreadable"] = journal.Unreadable.ToString(),
                    ["malformedEntries"] = journal.MalformedEntries.ToString(System.Globalization.CultureInfo.InvariantCulture),
                });
        }
        foreach (var alert in alerts)
        {
            b.Add(
                SeverityOf(alert),
                $"{alert.Source}/{alert.Kind}",
                $"{alert.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} — {alert.Detail}",
                new Dictionary<string, string?>
                {
                    ["time"] = alert.TimeUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                    ["source"] = alert.Source,
                    ["kind"] = alert.Kind,
                    ["detail"] = alert.Detail,
                });
        }
        var uncertain = alerts.Count(alert => SeverityOf(alert) == Severity.Unverified);
        return b.Build(journal.Unreadable || journal.MalformedEntries > 0
            ? "alert journal incomplete; some detection history may be unavailable"
            : alerts.Count == 0
            ? "no real-time detections recorded yet"
            : uncertain == 0
            ? $"{alerts.Count} recorded detection(s), newest first"
            : $"{alerts.Count - uncertain} recorded detection(s) and {uncertain} coverage notice(s), newest first");
    }

    /// <summary>
    /// A coverage-gain notice is <see cref="Severity.Unverified"/>, not <see cref="Severity.Notable"/>:
    /// it records entries whose arrival time WinSight cannot establish, not a detection (RA-03). It
    /// therefore stays visible without driving the exit code or reading as an attack.
    /// </summary>
    private static Severity SeverityOf(SecurityAlert alert) =>
        alert.Source == "Guardian" && alert.Kind == GuardianHost.CoverageGainKind
            ? Severity.Unverified
            : Severity.Notable;
}
