using System.Text.Json;

using WinSight.Reporting;
using WinSight.Response;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class ActionHistoryAccountingTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-history-accounting-").FullName;
    private string JournalPath => Path.Combine(_root, "history.jsonl");
    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Theory]
    [InlineData("evidence")]
    [InlineData("loss")]
    [InlineData("unknown-prior")]
    public void HistoricalAccountingAloneIsInformationalAndRetainsCountersAndPaths(string history)
    {
        WriteEntry();
        if (history == "evidence")
        {
            File.WriteAllText(JournalPath + ".corrupt.jsonl", "old evidence");
        }
        else
        {
            File.WriteAllText(JournalPath + ".evidence.json", JsonSerializer.Serialize(new
            {
                Version = 1,
                DiscardedBytes = history == "loss" ? 12L : 0L,
                DiscardedFiles = history == "loss" ? 1L : 0L,
                LossReason = "evidence-budget",
                PriorCountersUnknown = history == "unknown-prior",
                NextSlot = 0,
                PendingSlot = -1,
                PendingBytes = 0L,
                PendingSha256 = (string?)null,
            }));
        }
        var before = Directory.GetFiles(_root).ToDictionary(x => x, File.ReadAllBytes);
        var report = Adapters.Actions(JournalPath, 200);
        Assert.Equal(0, report.NotableCount);
        var coverage = Assert.Single(report.Items, x => x.Fields["kind"] == "actionJournalCoverage");
        Assert.Equal(Severity.Info, coverage.Severity);
        Assert.Contains("historical", coverage.Title, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(JournalPath, coverage.Fields["journalPath"]);
        Assert.Equal(JournalPath + ".evidence.json", coverage.Fields["evidenceMetadataPath"]);
        for (var slot = 0; slot < 4; slot++)
        {
            Assert.Equal(JournalPath + (slot == 0 ? ".corrupt.jsonl" : $".corrupt.{slot}.jsonl"), coverage.Fields[$"evidenceSlot{slot}Path"]);
        }
        Assert.Equal(history == "loss" ? "12" : "0", coverage.Fields["discardedEvidenceBytes"]);
        Assert.Equal(history == "unknown-prior" ? "true" : "false", coverage.Fields["evidenceCountersUnknown"]);
        Assert.DoesNotContain("incomplete", report.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(before.Keys.Order(), Directory.GetFiles(_root).Order());
        Assert.All(before, pair => Assert.Equal(pair.Value, File.ReadAllBytes(pair.Key)));
    }

    [Theory]
    [InlineData("malformed")]
    [InlineData("unavailable-evidence")]
    [InlineData("pending")]
    [InlineData("read-limit")]
    public void CurrentCoverageProblemsRemainNotable(string problem)
    {
        WriteEntry();
        if (problem == "malformed")
        {
            File.AppendAllText(JournalPath, "{ malformed\n");
        }
        else if (problem == "unavailable-evidence")
        {
            Directory.CreateDirectory(JournalPath + ".corrupt.2.jsonl");
        }
        else if (problem == "pending")
        {
            File.WriteAllText(JournalPath + ".evidence.json", JsonSerializer.Serialize(new
            {
                Version = 1,
                DiscardedBytes = 0L,
                DiscardedFiles = 0L,
                LossReason = "",
                PriorCountersUnknown = false,
                NextSlot = 0,
                PendingSlot = 0,
                PendingBytes = 0L,
                PendingSha256 = new string('0', 64),
            }));
        }
        else
        {
            File.WriteAllText(JournalPath, string.Concat(Enumerable.Repeat(File.ReadAllText(JournalPath), 10_001)));
        }
        var report = Adapters.Actions(JournalPath, problem == "read-limit" ? 0 : 200);
        Assert.True(report.NotableCount > 0);
        Assert.Equal(Severity.Notable, Assert.Single(report.Items, x => x.Fields["kind"] == "actionJournalCoverage").Severity);
    }

    private void WriteEntry() => File.AppendAllText(JournalPath, JsonSerializer.Serialize(new ActionJournalEntry(
        Guid.NewGuid(), ResponseActionKind.AddRule, ResponseOutcome.Succeeded, "target", DateTimeOffset.UtcNow, true)) + "\n");
}
