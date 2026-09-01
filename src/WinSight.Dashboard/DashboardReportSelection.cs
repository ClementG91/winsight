using WinSight.Reporting;

namespace WinSight.Dashboard;

internal sealed record DashboardReportSelection(IReadOnlyList<ToolReport> Reports, bool Categorize)
{
    public static DashboardReportSelection Unavailable { get; } = new([], Categorize: false);
    public bool Available => Reports.Count > 0;
}
