using WinSight.Application;
using WinSight.Reporting;
using Xunit;

namespace WinSight.Mcp.Tests;

public sealed class McpResultProjectorTests
{
    [Fact]
    public void Catalog_ExactlyMatchesApplicationScanners()
    {
        Assert.Equal(
            Adapters.SnapshotCommands.Order(),
            McpCatalog.Scanners.Select(scanner => scanner.Name).Order());
        Assert.Equal(Adapters.OverviewCommands.Count, McpCatalog.Scanners.Count(scanner => scanner.InOverview));
    }

    [Fact]
    public void SummaryMode_ReturnsCountsWithoutEvidence()
    {
        var result = McpResultProjector.Project(
            [SampleReport()],
            includeEvidence: false,
            includeSensitive: false,
            sensitiveEnabled: false,
            maxItemsPerReport: 10);

        var report = Assert.Single(result.Reports);
        Assert.False(result.EvidenceIncluded);
        Assert.False(result.SensitiveFieldsIncluded);
        Assert.Equal(2, report.TotalItemCount);
        Assert.Equal(1, report.NotableCount);
        Assert.Equal(0, report.ReturnedItemCount);
        Assert.Empty(report.Items);
        Assert.False(report.Truncated);
    }

    [Fact]
    public void Evidence_IsBoundedAndMarkedTruncated()
    {
        var result = McpResultProjector.Project(
            [SampleReport()],
            includeEvidence: true,
            includeSensitive: false,
            sensitiveEnabled: false,
            maxItemsPerReport: 1);

        var report = Assert.Single(result.Reports);
        Assert.Equal(1, report.ReturnedItemCount);
        Assert.Single(report.Items);
        Assert.True(report.Truncated);
    }

    [Fact]
    public void ProtectedEvidence_RedactsProfileAndDropsCommandFields()
    {
        var result = McpResultProjector.Project(
            [SampleReport()],
            includeEvidence: true,
            includeSensitive: false,
            sensitiveEnabled: false,
            maxItemsPerReport: 10);

        var finding = Assert.Single(result.Reports).Items[0];
        Assert.Contains("%USERPROFILE%", finding.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("command", finding.Fields.Keys, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("commandLine", finding.Fields.Keys, StringComparer.OrdinalIgnoreCase);
        Assert.Equal("%USERPROFILE%\\payload.exe", finding.Fields["image"]);
    }

    [Fact]
    public void SensitiveEvidence_RequiresServerSideGate()
    {
        var error = Assert.Throws<InvalidOperationException>(() => McpResultProjector.Project(
            [SampleReport()],
            includeEvidence: true,
            includeSensitive: true,
            sensitiveEnabled: false,
            maxItemsPerReport: 10));

        Assert.Contains("disabled", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SensitiveEvidence_PreservesRawFieldsWhenExplicitlyEnabled()
    {
        var result = McpResultProjector.Project(
            [SampleReport()],
            includeEvidence: true,
            includeSensitive: true,
            sensitiveEnabled: true,
            maxItemsPerReport: 10);

        var finding = Assert.Single(result.Reports).Items[0];
        Assert.True(result.SensitiveFieldsIncluded);
        Assert.Equal("secret-value", finding.Fields["commandLine"]);
        Assert.Contains(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), finding.Detail);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(201)]
    public void EvidenceLimit_IsStrictlyBounded(int limit)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => McpResultProjector.Project(
            [SampleReport()],
            includeEvidence: true,
            includeSensitive: false,
            sensitiveEnabled: false,
            maxItemsPerReport: limit));
    }

    private static ToolReport SampleReport()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return new ToolReport.Builder("persistence")
            .Add(
                Severity.Notable,
                "Run/Payload",
                Path.Combine(profile, "payload.exe"),
                new Dictionary<string, string?>
                {
                    ["image"] = Path.Combine(profile, "payload.exe"),
                    ["command"] = "payload.exe --token secret",
                    ["commandLine"] = "secret-value",
                    ["signature"] = "Unsigned",
                    ["signer"] = null,
                })
            .Add(
                Severity.Info,
                "Service/Expected",
                @"C:\Windows\System32\expected.exe",
                new Dictionary<string, string?> { ["signature"] = "SignedTrusted" })
            .Build("2 item(s), 1 flagged");
    }
}
