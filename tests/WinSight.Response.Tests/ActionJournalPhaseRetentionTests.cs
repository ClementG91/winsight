using System.Text.Json;

using Xunit;

namespace WinSight.Response.Tests;

public sealed class ActionJournalPhaseRetentionTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-phase-retention-").FullName;
    private string PathName => Path.Combine(_root, "history.jsonl");
    private static readonly DateTimeOffset Start = new(2026, 10, 3, 0, 0, 0, TimeSpan.Zero);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private static ActionJournalEntry Row(Guid id, ActionJournalPhase phase, int seconds, string target = "target") =>
        new(id, ResponseActionKind.AddRule, ResponseOutcome.Succeeded, target, Start.AddSeconds(seconds), true,
            Phase: phase);

    private void Seed(params ActionJournalEntry[] rows) =>
        File.WriteAllLines(PathName, rows.Select(e => JsonSerializer.Serialize(e)));

    private ActionJournalEntry[] Physical() => File.ReadAllLines(PathName)
        .Select(s => JsonSerializer.Deserialize<ActionJournalEntry>(s)!).ToArray();

    [Fact]
    public void UndoNeverDeletesTheRetainedPreparedRecordsOrTheirTimestamps()
    {
        var first = Guid.NewGuid();
        var second = Guid.NewGuid();
        var undo = Guid.NewGuid();
        var rows = new[] { Row(first, ActionJournalPhase.Prepared, 1), Row(first, ActionJournalPhase.Completed, 2),
            Row(second, ActionJournalPhase.Prepared, 3), Row(second, ActionJournalPhase.Completed, 4) };
        Seed(rows);
        Assert.Equal(ActionJournalWriteStatus.Updated, new ActionJournal(PathName).TryMarkUndone(first, undo).Status);
        Assert.Equal(rows.Select((e, i) => i == 1 ? e with { UndoneByActionId = undo } : e), Physical());
        Assert.Equal(2, new ActionJournal(PathName).Read().Count);
    }

    [Fact]
    public void RotationRetainsCompleteAvailablePairsAtThePhysicalLineBoundary()
    {
        var rows = Enumerable.Range(0, 5000).SelectMany(i =>
        {
            var id = Guid.NewGuid();
            return new[] { Row(id, ActionJournalPhase.Prepared, 2 * i), Row(id, ActionJournalPhase.Completed, 2 * i + 1) };
        }).ToArray();
        Seed(rows);
        var latest = Row(Guid.NewGuid(), ActionJournalPhase.Prepared, 10_001);
        Assert.Equal(ActionJournalWriteStatus.Rotated, new ActionJournal(PathName).TryAppendWithStatus(latest).Status);
        var retained = Physical();
        Assert.Equal(4999, retained.Length);
        Assert.Equal(rows.TakeLast(4998).Append(latest), retained);
        Assert.All(retained.Where(e => e.ActionId != latest.ActionId).GroupBy(e => e.ActionId), g => Assert.Equal(2, g.Count()));
        Assert.InRange(new FileInfo(PathName).Length, 1, ActionJournalReader.MaxBytes / 2);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void BudgetsNeverSplitAnAvailableActionGroup(bool lineBoundary)
    {
        var older = Guid.NewGuid();
        var newer = Guid.NewGuid();
        var rows = new[] { Row(older, ActionJournalPhase.Prepared, 1), Row(older, ActionJournalPhase.Completed, 2),
            Row(newer, ActionJournalPhase.Prepared, 3), Row(newer, ActionJournalPhase.Completed, 4) };
        var byteBudget = lineBoundary ? 4096 : rows.Skip(1).Sum(e => ActionJournalStorage.Encode(e)!.Length);
        Assert.True(ActionJournalStorage.Replace(PathName, rows.Reverse(), byteBudget, lineBoundary ? 3 : 4,
            ActionJournalWriteStatus.Updated).Durable);
        Assert.Equal(rows.Skip(2), Physical());
    }

    [Fact]
    public void InterleavedPhasesKeepTheirOriginalPhysicalOrder()
    {
        var first = Guid.NewGuid();
        var second = Guid.NewGuid();
        var rows = new[] { Row(first, ActionJournalPhase.Prepared, 1), Row(second, ActionJournalPhase.Prepared, 2),
            Row(first, ActionJournalPhase.Completed, 3), Row(second, ActionJournalPhase.Completed, 4) };
        Seed(rows);
        var undo = Guid.NewGuid();
        Assert.True(new ActionJournal(PathName).TryMarkUndone(first, undo).Durable);
        Assert.Equal(rows.Select((e, i) => i == 2 ? e with { UndoneByActionId = undo } : e), Physical());
    }

    [Fact]
    public void CompactionKeepsOnlyTheNewestDuplicateOfEachPhase()
    {
        var id = Guid.NewGuid();
        var rows = new[] { Row(id, ActionJournalPhase.Prepared, 1, "old intent"), Row(id, ActionJournalPhase.Prepared, 2),
            Row(id, ActionJournalPhase.Completed, 3, "old completion"), Row(id, ActionJournalPhase.Completed, 4) };
        Assert.True(ActionJournalStorage.Replace(PathName, rows.Reverse(), 4096, 4,
            ActionJournalWriteStatus.Updated).Durable);
        Assert.Equal(new[] { rows[1], rows[3] }, Physical());
    }

    [Fact]
    public void PreparedOnlyActionsAreRetainedWithoutInventingCompletion()
    {
        var incomplete = Row(Guid.NewGuid(), ActionJournalPhase.Prepared, 1);
        var id = Guid.NewGuid();
        var rows = new[] { incomplete, Row(id, ActionJournalPhase.Prepared, 2), Row(id, ActionJournalPhase.Completed, 3) };
        Seed(rows);
        var undo = Guid.NewGuid();
        Assert.True(new ActionJournal(PathName).TryMarkUndone(id, undo).Durable);
        Assert.Equal(rows.Select((e, i) => i == 2 ? e with { UndoneByActionId = undo } : e), Physical());
        Assert.Equal(ActionJournalWriteStatus.TargetNotFound, new ActionJournal(PathName)
            .TryMarkUndone(incomplete.ActionId, undo).Status);
    }

    [Fact]
    public void PublicHistoryKeepsTheNewestLogicalEntryPerAction()
    {
        var first = Guid.NewGuid();
        var second = Guid.NewGuid();
        var rows = new[] { Row(first, ActionJournalPhase.Prepared, 1), Row(second, ActionJournalPhase.Prepared, 2),
            Row(first, ActionJournalPhase.Completed, 3), Row(second, ActionJournalPhase.Completed, 4) };
        Seed(rows);
        Assert.Equal(new[] { rows[3], rows[2] }, new ActionJournal(PathName).Read());
        Assert.Equal(rows[3], Assert.Single(new ActionJournal(PathName).Read(1)));
    }

    [Fact]
    public void UndoRefusesPublicationIfTheAnnotationWouldEvictItsOwnAction()
    {
        var rows = Enumerable.Range(0, 4000).SelectMany(i =>
        {
            var id = Guid.NewGuid();
            return new[] { Row(id, ActionJournalPhase.Prepared, 2 * i), Row(id, ActionJournalPhase.Completed, 2 * i + 1) };
        }).ToArray();
        var remaining = ActionJournalReader.MaxBytes - 2 - rows.Sum(e => ActionJournalStorage.Encode(e)!.Length);
        for (var i = 0; remaining > 0 && i < rows.Length; i++)
        {
            var add = Math.Min(remaining, 2048 - rows[i].Target.Length);
            rows[i] = rows[i] with { Target = rows[i].Target + new string('a', add) };
            remaining -= add;
        }
        Assert.Equal(0, remaining);
        using (var output = File.Create(PathName))
        {
            foreach (var row in rows) { output.Write(ActionJournalStorage.Encode(row)!); }
        }
        Assert.Equal(ActionJournalReader.MaxBytes - 2, new FileInfo(PathName).Length);
        var original = File.ReadAllBytes(PathName);
        var result = new ActionJournal(PathName).TryMarkUndone(rows[0].ActionId, Guid.NewGuid());
        Assert.False(result.Durable, "An evicted target cannot be reported as durably annotated.");
        Assert.Equal("RetentionLimit", result.Status.ToString());
        Assert.Equal(original, File.ReadAllBytes(PathName));
        Assert.Equal(rows, Physical());
    }
}
