namespace WinSight.Dashboard;

public static class DashboardResultSummary
{
    public static string Format(LocalizationManager text, int resultCount, int attentionCount)
    {
        var results = text.Format(
            resultCount == 1 ? "ResultCountSingle" : "ResultCountPlural",
            resultCount);
        var attention = text.Format(
            attentionCount == 1 ? "AttentionCountSingle" : "AttentionCountPlural",
            attentionCount);
        return text.Format("ResultsSummary", results, attention);
    }
}
