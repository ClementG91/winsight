using WinSight.Mcp;
using WinSight.Reporting;
using Xunit;

namespace WinSight.Mcp.Tests;

/// <summary>
/// How much of a report one MCP response carries, and how a client reaches the rest.
/// </summary>
/// <remarks>
/// <b>Two ways the old shape failed.</b>
///
/// The cap was 200 items per report and there was no way to ask for the next 200. A persistence
/// scan on a real desktop returns 4538 items; a model was handed the first page, told
/// <c>truncated: true</c>, and given nothing it could do about it. "There is more evidence and you
/// cannot have it" is a worse answer than a smaller page with a way to continue.
///
/// And nothing bounded the size. An item carries a title, a detail and up to fifteen fields, and
/// those fields hold registry values, command lines and certificate subjects whose length is decided
/// by the machine's contents - none of it written by this server. Two hundred items of ordinary
/// evidence is tens of kilobytes; two hundred whose fields happen to be long is megabytes, and a
/// response large enough to fill the model's context is a denial of the tool arranged by whoever
/// wrote the registry value.
/// </remarks>
public sealed class McpPaginationTests
{
    private static ToolReport Report(int items, int fieldLength = 8)
    {
        var builder = new ToolReport.Builder("persistence");
        for (var index = 0; index < items; index++)
        {
            builder.Add(
                Severity.Info,
                $"item-{index}",
                "detail",
                new Dictionary<string, string?> { ["value"] = new('x', fieldLength) });
        }
        return builder.Build($"{items} item(s)");
    }

    private static McpScannerReport Project(ToolReport report, int maxItems, int offset = 0) =>
        McpResultProjector.Project(
            [report],
            includeEvidence: true,
            includeSensitive: false,
            sensitiveEnabled: false,
            maxItems,
            offset).Reports[0];

    [Fact]
    public void TheFirstPageStartsAtTheBeginningAndSaysMoreRemains()
    {
        var page = Project(Report(500), maxItems: 50);

        Assert.Equal(0, page.Offset);
        Assert.Equal(50, page.ReturnedItemCount);
        Assert.Equal(500, page.TotalItemCount);
        Assert.True(page.Truncated);
    }

    /// <summary>
    /// The contract the tool description promises: ask again with offset plus returnedItemCount.
    /// </summary>
    [Fact]
    public void TheNextPageContinuesWhereTheLastOneStopped()
    {
        var report = Report(500);

        var first = Project(report, maxItems: 50);
        var second = Project(report, maxItems: 50, offset: first.Offset + first.ReturnedItemCount);

        Assert.Equal(50, second.Offset);
        Assert.Equal("item-0", Strip(first.Items[0].Title));
        Assert.Equal("item-50", Strip(second.Items[0].Title));
    }

    [Fact]
    public void TheLastPageIsNotMarkedTruncated()
    {
        var page = Project(Report(120), maxItems: 50, offset: 100);

        Assert.Equal(20, page.ReturnedItemCount);
        Assert.False(page.Truncated);
    }

    /// <summary>An offset past the end is an empty page, not an error and not a wrapped one.</summary>
    [Fact]
    public void AnOffsetPastTheEndReturnsNothing()
    {
        var page = Project(Report(10), maxItems: 50, offset: 1000);

        Assert.Empty(page.Items);
        Assert.False(page.Truncated);
        Assert.Equal(10, page.TotalItemCount);
    }

    [Fact]
    public void ANegativeOffsetIsRefused() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => Project(Report(10), maxItems: 50, offset: -1));

    /// <summary>
    /// The size budget stops a page whose items are individually enormous, and says so separately
    /// from truncation - the remedy is a smaller page, not a later one.
    /// </summary>
    [Fact]
    public void AnOversizedPageStopsAtTheBudgetAndSaysWhy()
    {
        var page = Project(Report(200, fieldLength: 20_000), maxItems: 200);

        Assert.True(page.BudgetExhausted);
        Assert.True(page.ReturnedItemCount < 200);
        Assert.True(page.ReturnedItemCount > 0);
    }

    /// <summary>
    /// A single item larger than the whole budget is still returned. A page that came back empty
    /// would say less than one that returns the item and admits it was oversized.
    /// </summary>
    [Fact]
    public void OneItemLargerThanTheBudgetIsStillReturned()
    {
        var page = Project(
            Report(1, fieldLength: McpResultProjector.EvidenceCharacterBudget * 2), maxItems: 50);

        Assert.Single(page.Items);
    }

    /// <summary>An ordinary page is nowhere near the budget and must not be trimmed by it.</summary>
    [Fact]
    public void AnOrdinaryPageIsNotTrimmed()
    {
        var page = Project(Report(50), maxItems: 50);

        Assert.False(page.BudgetExhausted);
        Assert.Equal(50, page.ReturnedItemCount);
    }

    /// <summary>
    /// Without evidence there is nothing to page through, and the offset must not leak into the
    /// response as though there were.
    /// </summary>
    [Fact]
    public void ASummaryOnlyResponseCarriesNoPage()
    {
        var summary = McpResultProjector.Project(
            [Report(500)],
            includeEvidence: false,
            includeSensitive: false,
            sensitiveEnabled: false,
            maxItemsPerReport: 50,
            offset: 100).Reports[0];

        Assert.Empty(summary.Items);
        Assert.Equal(0, summary.Offset);
        Assert.False(summary.Truncated);
        Assert.Equal(500, summary.TotalItemCount);
    }

    /// <summary>Titles arrive wrapped in the untrusted-text delimiters; this reads through them.</summary>
    private static string Strip(string wrapped) =>
        wrapped.Replace(UntrustedText.OpenDelimiter, string.Empty, StringComparison.Ordinal)
            .Replace(UntrustedText.CloseDelimiter, string.Empty, StringComparison.Ordinal);
}
