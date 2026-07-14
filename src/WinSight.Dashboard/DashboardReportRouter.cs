using WinSight.Reporting;

namespace WinSight.Dashboard;

/// <summary>
/// Selects only reports that belong to the active navigation item. Keeping this
/// policy outside the window makes stale cross-tool findings impossible to hide in
/// event-handler state and gives it deterministic unit coverage.
/// </summary>
public static class DashboardReportRouter
{
    public static DashboardReportSelection Select(
        DashboardTool tool,
        string? lastScanCommand,
        IReadOnlyList<ToolReport> reports)
    {
        if (tool.Command.Equals("all", StringComparison.OrdinalIgnoreCase))
        {
            return lastScanCommand?.Equals("all", StringComparison.OrdinalIgnoreCase) == true
                ? new DashboardReportSelection(reports, Categorize: true)
                : DashboardReportSelection.Unavailable;
        }

        var report = reports.FirstOrDefault(candidate =>
            candidate.Tool.Equals(tool.ReportName, StringComparison.OrdinalIgnoreCase));
        return report is null
            ? DashboardReportSelection.Unavailable
            : new DashboardReportSelection([report], Categorize: false);
    }
}

public sealed record DashboardReportSelection(IReadOnlyList<ToolReport> Reports, bool Categorize)
{
    public static DashboardReportSelection Unavailable { get; } = new([], Categorize: false);
    public bool Available => Reports.Count > 0;
}
