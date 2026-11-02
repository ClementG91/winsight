using System.Text.Json;

using WinSight.Reporting;
using WinSight.Response;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class JournalPathFamilyReportingTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-path-report-").FullName;
    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Theory]
    [InlineData(219)]
    [InlineData(255)]
    public void AWriteFamilyRefusalDoesNotPretendReadableHistoryIsIncomplete(int units)
    {
        var path = Path.Combine(_root, new string('j', units));
        var entry = new ActionJournalEntry(Guid.NewGuid(), ResponseActionKind.AddRule,
            ResponseOutcome.Succeeded, "existing successful action", DateTimeOffset.UtcNow, true);
        File.WriteAllText(path, JsonSerializer.Serialize(entry) + "\n");
        var before = File.ReadAllBytes(path);
        var report = Adapters.Actions(path, 200);
        Assert.Equal(1, report.NotableCount);
        var refusal = Assert.Single(report.Items, item => item.Fields["kind"] == "actionJournalWritePath");
        Assert.Equal(Severity.Notable, refusal.Severity);
        Assert.Equal("PathTooLong", refusal.Fields["writePathFailure"]);
        Assert.Contains("218", refusal.Detail, StringComparison.Ordinal);
        Assert.Equal(entry.ActionId.ToString(), Assert.Single(report.Items,
            item => item.Fields["kind"] == "responseAction").Fields["actionId"]);
        Assert.DoesNotContain("history incomplete", report.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("writes refused", report.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(before, File.ReadAllBytes(path));
        Assert.Single(Directory.GetFiles(_root));
    }
}
