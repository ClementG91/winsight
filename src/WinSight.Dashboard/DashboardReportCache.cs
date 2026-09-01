using WinSight.Reporting;

namespace WinSight.Dashboard;

/// <summary>
/// Keeps successful dashboard scans independently so running one tool cannot discard
/// valid results produced by the overview or another tool.
/// </summary>
internal sealed class DashboardReportCache
{
    private readonly Dictionary<(string Tool, bool FlaggedOnly), ToolReport> _reports = [];
    private readonly Dictionary<bool, IReadOnlyList<string>> _overviewReportNames = [];

    public void StoreOverview(IReadOnlyList<ToolReport> reports, bool flaggedOnly)
    {
        ArgumentNullException.ThrowIfNull(reports);

        var names = new List<string>(reports.Count);
        foreach (var report in reports)
        {
            _reports[Key(report.Tool, flaggedOnly)] = report;
            if (!names.Contains(report.Tool, StringComparer.OrdinalIgnoreCase))
            {
                names.Add(report.Tool);
            }
        }

        _overviewReportNames[flaggedOnly] = names;
    }

    public void Store(ToolReport report, bool flaggedOnly)
    {
        ArgumentNullException.ThrowIfNull(report);
        _reports[Key(report.Tool, flaggedOnly)] = report;
    }

    public DashboardReportSelection Select(DashboardTool tool, bool flaggedOnly)
    {
        ArgumentNullException.ThrowIfNull(tool);

        if (tool.Command.Equals("all", StringComparison.OrdinalIgnoreCase))
        {
            if (!_overviewReportNames.TryGetValue(flaggedOnly, out var overviewNames)
                || overviewNames.Count == 0)
            {
                return DashboardReportSelection.Unavailable;
            }

            var overview = overviewNames
                .Select(name => _reports.TryGetValue(Key(name, flaggedOnly), out var report) ? report : null)
                .Where(report => report is not null)
                .Cast<ToolReport>()
                .ToList();
            return overview.Count == 0
                ? DashboardReportSelection.Unavailable
                : new DashboardReportSelection(overview, Categorize: true);
        }

        return _reports.TryGetValue(Key(tool.ReportName, flaggedOnly), out var selected)
            ? new DashboardReportSelection([selected], Categorize: false)
            : DashboardReportSelection.Unavailable;
    }

    private static (string Tool, bool FlaggedOnly) Key(string tool, bool flaggedOnly) =>
        (tool.ToUpperInvariant(), flaggedOnly);
}
