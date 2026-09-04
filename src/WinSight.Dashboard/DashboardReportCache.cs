using WinSight.Reporting;

namespace WinSight.Dashboard;

/// <summary>
/// Keeps successful dashboard scans independently so running one tool cannot discard
/// valid results produced by the overview or another tool.
/// </summary>
internal sealed class DashboardReportCache
{
    private readonly Dictionary<(string Tool, bool FlaggedOnly), CacheEntry> _reports = [];
    private readonly Dictionary<bool, CacheEntry> _overviews = [];
    private readonly Func<DateTimeOffset> _utcNow;

    public DashboardReportCache(Func<DateTimeOffset>? utcNow = null)
    {
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
    }

    public void StoreOverview(IReadOnlyList<ToolReport> reports, bool flaggedOnly)
    {
        ArgumentNullException.ThrowIfNull(reports);

        var capturedAt = _utcNow();
        var snapshot = reports.ToArray();
        _overviews[flaggedOnly] = new CacheEntry(snapshot, capturedAt);

        foreach (var report in reports)
        {
            _reports[Key(report.Tool, flaggedOnly)] = new CacheEntry([report], capturedAt);
        }
    }

    public void Store(ToolReport report, bool flaggedOnly)
    {
        ArgumentNullException.ThrowIfNull(report);
        _reports[Key(report.Tool, flaggedOnly)] = new CacheEntry([report], _utcNow());
    }

    public void Remove(DashboardTool tool, bool flaggedOnly)
    {
        ArgumentNullException.ThrowIfNull(tool);
        if (tool.Command.Equals("all", StringComparison.OrdinalIgnoreCase))
        {
            _overviews.Remove(flaggedOnly);
            return;
        }

        _reports.Remove(Key(tool.ReportName, flaggedOnly));
    }

    public DashboardReportSelection Select(DashboardTool tool, bool flaggedOnly)
    {
        ArgumentNullException.ThrowIfNull(tool);

        if (tool.Command.Equals("all", StringComparison.OrdinalIgnoreCase))
        {
            if (!_overviews.TryGetValue(flaggedOnly, out var overview)
                || overview.Reports.Count == 0)
            {
                return DashboardReportSelection.Unavailable;
            }

            return new DashboardReportSelection(
                overview.Reports, Categorize: true, overview.CapturedAt);
        }

        return _reports.TryGetValue(Key(tool.ReportName, flaggedOnly), out var selected)
            ? new DashboardReportSelection(
                selected.Reports, Categorize: false, selected.CapturedAt)
            : DashboardReportSelection.Unavailable;
    }

    private static (string Tool, bool FlaggedOnly) Key(string tool, bool flaggedOnly) =>
        (tool.ToUpperInvariant(), flaggedOnly);

    private sealed record CacheEntry(IReadOnlyList<ToolReport> Reports, DateTimeOffset CapturedAt);
}
