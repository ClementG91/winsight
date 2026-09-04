using WinSight.Reporting;

namespace WinSight.Dashboard;

internal sealed record DashboardReportSelection(
    IReadOnlyList<ToolReport> Reports,
    bool Categorize,
    DateTimeOffset? CapturedAt)
{
    public static DashboardReportSelection Unavailable { get; } = new(
        [], Categorize: false, CapturedAt: null);
    public bool Available => Reports.Count > 0;
}
