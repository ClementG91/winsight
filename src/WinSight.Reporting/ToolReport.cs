namespace WinSight.Reporting;

/// <summary>How much attention an item deserves. Kept deliberately small; a tool's
/// own model carries the domain detail.</summary>
public enum Severity
{
    /// <summary>Normal, expected item.</summary>
    Info,

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
    /// <summary>Count of Notable items — the basis for a non-zero process exit.</summary>
    public int NotableCount => Items.Count(i => i.Severity == Severity.Notable);

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
