namespace WinSight.Reporting;

/// <summary>How much attention an item deserves. Kept deliberately small; a tool's
/// own model carries the domain detail.</summary>
public enum Severity
{
    /// <summary>Normal, expected item.</summary>
    Info,

    /// <summary>
    /// The check could not complete, so nothing is known either way.
    /// </summary>
    /// <remarks>
    /// <b>Why a third level exists.</b> With only Info and Notable, "the file this registration
    /// points at is not on disk, so its signature was never checked" arrived at exactly the weight
    /// of "an unsigned DLL is registered as a debugger for every launch of this executable". An
    /// orphaned registration left by an OEM uninstaller and a live IFEO hijack produced the same
    /// signal, and the first is far more common - which made it the dominant source of noise in the
    /// product and taught an operator to skim the flagged list.
    ///
    /// This is the same distinction the codebase already draws everywhere else, between "I looked
    /// and found nothing" and "I could not look": PersistenceCoverage, AcquisitionSnapshot,
    /// FileMissing being kept apart from Unsigned. It simply had nowhere to land in the severity
    /// model.
    ///
    /// <b>It does not drive the exit code.</b> An incomplete acquisition is not a finding, and a
    /// scheduled task that exits non-zero because a driver registration is stale is a scheduled
    /// task somebody turns off.
    /// </remarks>
    Unverified,

    /// <summary>Worth a look (unsigned, live, external, ...). Drives the exit code.</summary>
    Notable,
}

/// <summary>
/// One line of a tool's findings in the tool-agnostic report model. Fields carries
/// the structured key/values for the JSON contract; Title/Detail are the human view.
/// </summary>
public sealed record ReportItem(
    Severity Severity,
    string Title,
    string Detail,
    IReadOnlyDictionary<string, string?> Fields);

/// <summary>
/// A single tool's output in a shared shape so one renderer serves every tool (text
/// or JSON), and new tools plug in without touching the CLI's rendering. This is the
/// stable contract a future GUI/dashboard consumes.
/// </summary>
public sealed record ToolReport(string Tool, string Summary, IReadOnlyList<ReportItem> Items)
{
    /// <summary>Count of Notable items, the basis for a non-zero process exit.</summary>
    public int NotableCount => Items.Count(i => i.Severity == Severity.Notable);

    /// <summary>
    /// Items whose check could not complete. Reported beside the notable count and deliberately not
    /// added to it: these are gaps in the observation, not findings about the machine.
    /// </summary>
    public int UnverifiedCount => Items.Count(i => i.Severity == Severity.Unverified);

    /// <summary>Fluent builder to keep tool adapters terse.</summary>
    public sealed class Builder(string tool)
    {
        private readonly List<ReportItem> _items = [];

        public Builder Add(Severity severity, string title, string detail, IReadOnlyDictionary<string, string?> fields)
        {
            _items.Add(new ReportItem(severity, title, detail, fields));
            return this;
        }

        public ToolReport Build(string summary) => new(tool, summary, _items);
    }
}
