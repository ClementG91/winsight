using System.Text.Json;

using WinSight.Reporting;
using WinSight.Response;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class FutureRuleStoreReportingTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-future-report-").FullName;
    private string PathName => Path.Combine(_root, "rules.json");
    private RuleStore Store => new(PathName);
    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Theory]
    [InlineData("Scope")]
    [InlineData("Decision")]
    [InlineData("Duration")]
    public void UnknownEnumEntriesAreInactiveRetainedAndReportedSeparatelyFromInvalidData(string field)
    {
        var id = WriteFuture(field);
        var before = File.ReadAllBytes(PathName);
        var presenter = new GuardianAlertPresenter(rules: Store,
            journal: new ActionJournal(Path.Combine(_root, "actions.jsonl")));
        var report = Adapters.Rules(presenter);

        Assert.Equal(0, report.NotableCount);
        var coverage = Assert.Single(report.Items, item => item.Fields["kind"] == "ruleStoreCoverage");
        Assert.Equal(Severity.Info, coverage.Severity);
        Assert.Equal("0", coverage.Fields["ignoredEntries"]);
        Assert.Equal("1", coverage.Fields["retainedUnsupportedEntries"]);
        Assert.DoesNotContain(report.Items, item => item.Fields["kind"] == "responseRule");
        Assert.Equal(before, File.ReadAllBytes(PathName));
        Assert.Null(Store.Match(RuleScopeKind.Persistence, item: "run:future"));
        var neighbor = Rule();
        Assert.NotNull(Store.Add(neighbor));
        using var stored = JsonDocument.Parse(File.ReadAllBytes(PathName));
        Assert.Contains(stored.RootElement.GetProperty("Rules").EnumerateArray(), entry => entry.GetProperty("Id").GetGuid() == id);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FutureRevocationRemainsJournalledAndCompletionFailureIsPartiallyApplied(bool refuseCompletion)
    {
        var id = WriteFuture("Scope");
        var journal = new RecordingJournal(refuseCompletion);
        var presenter = new GuardianAlertPresenter(rules: Store, journal: journal);

        var outcome = presenter.Revoke(id, out var result);

        Assert.Equal(refuseCompletion ? ResponseOutcome.PartiallyApplied : ResponseOutcome.Succeeded, outcome);
        Assert.Equal(outcome, result.Outcome);
        Assert.False(result.Reversible);
        var prepared = Assert.Single(journal.Entries, entry => entry.Phase == ActionJournalPhase.Prepared);
        Assert.Equal(ResponseActionKind.RemoveRule, prepared.Kind);
        if (refuseCompletion)
        {
            Assert.Single(journal.Entries);
        }
        else
        {
            var completed = Assert.Single(journal.Entries, entry => entry.Phase == ActionJournalPhase.Completed);
            Assert.Equal(prepared.ActionId, completed.ActionId);
            Assert.Equal(ResponseOutcome.Succeeded, completed.Outcome);
        }
        if (refuseCompletion)
        {
            Assert.Empty(journal.UndoCalls);
        }
        else
        {
            var undo = Assert.Single(journal.UndoCalls);
            Assert.Equal(id, undo.RuleId);
            Assert.Equal(prepared.ActionId, undo.UndoId);
        }
        using var stored = JsonDocument.Parse(File.ReadAllBytes(PathName));
        Assert.Empty(stored.RootElement.GetProperty("Rules").EnumerateArray());
        Assert.Equal(ResponseOutcome.TargetNotFound, Store.RemoveWithOutcome(id));
    }

    private Guid WriteFuture(string field)
    {
        var rule = Rule() with { Item = "run:future" };
        var json = System.Text.Json.Nodes.JsonNode.Parse(JsonSerializer.Serialize(rule))!;
        json[field] = 99;
        File.WriteAllText(PathName, "{\"Version\":1,\"Rules\":[" + json.ToJsonString() + "]}");
        return rule.Id;
    }

    private static ResponseRule Rule() => new(Guid.NewGuid(), RuleScopeKind.Persistence, RuleDecision.Allow,
        RuleDuration.Permanent, DateTimeOffset.UtcNow, Item: "run:neighbor");

    private sealed class RecordingJournal(bool refuseCompletion) : IActionJournal
    {
        public List<ActionJournalEntry> Entries { get; } = [];
        public bool TryAppend(ActionJournalEntry entry)
        {
            if (refuseCompletion && entry.Phase == ActionJournalPhase.Completed)
            {
                return false;
            }
            Entries.Add(entry);
            return true;
        }
        public List<(Guid RuleId, Guid UndoId)> UndoCalls { get; } = [];
        public void MarkUndone(Guid actionId, Guid undoActionId) => UndoCalls.Add((actionId, undoActionId));
        public IReadOnlyList<ActionJournalEntry> Read(int max = 200) => Entries;
    }
}
