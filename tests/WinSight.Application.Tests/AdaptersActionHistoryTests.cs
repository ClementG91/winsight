using WinSight.Application;
using WinSight.Reporting;
using WinSight.Response;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class AdaptersActionHistoryTests : IDisposable
{
    private readonly string _journal = Path.Combine(
        Path.GetTempPath(), $"winsight-actions-{Guid.NewGuid():N}.jsonl");

    public void Dispose()
    {
        if (File.Exists(_journal))
        {
            File.Delete(_journal);
        }
    }

    [Fact]
    public void AnEmptyJournalReportsNoHistoryRatherThanAFinding()
    {
        var report = Adapters.Actions(_journal, 200);

        Assert.Equal("actions", report.Tool);
        Assert.Empty(report.Items);
        Assert.Equal(0, report.NotableCount);
        Assert.Contains("no response actions", report.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ASucceededActionIsHistoryAndAFailedOneIsNotable()
    {
        var journal = new ActionJournal(_journal);
        Assert.True(journal.TryAppend(new ActionJournalEntry(
            Guid.NewGuid(), ResponseActionKind.SuspendProcess, ResponseOutcome.Succeeded,
            "enc.exe", DateTimeOffset.UtcNow, Reversible: true)));
        Assert.True(journal.TryAppend(new ActionJournalEntry(
            Guid.NewGuid(), ResponseActionKind.TerminateProcess, ResponseOutcome.TargetProtected,
            "lsass.exe", DateTimeOffset.UtcNow, Reversible: false)));

        var report = Adapters.Actions(_journal, 200);

        Assert.Equal(2, report.Items.Count);
        // Newest first: the refused terminate is the most recent entry.
        var newest = report.Items[0];
        Assert.Equal(Severity.Notable, newest.Severity);
        Assert.Equal("TargetProtected", newest.Fields["outcome"]);
        Assert.Equal("responseAction", newest.Fields["kind"]);

        var suspend = report.Items[1];
        Assert.Equal(Severity.Info, suspend.Severity);
        Assert.Equal("SuspendProcess", suspend.Fields["action"]);
        Assert.Equal("true", suspend.Fields["reversible"]);
        Assert.Equal(1, report.NotableCount);
    }

    [Fact]
    public void AnUndoneActionIsMarkedAndCarriesTheUndoId()
    {
        var journal = new ActionJournal(_journal);
        var actionId = Guid.NewGuid();
        var undoId = Guid.NewGuid();
        journal.TryAppend(new ActionJournalEntry(
            actionId, ResponseActionKind.QuarantinePersistence, ResponseOutcome.Succeeded,
            @"HKCU\...\Run\Updater", DateTimeOffset.UtcNow, Reversible: true));
        journal.MarkUndone(actionId, undoId);

        var item = Assert.Single(Adapters.Actions(_journal, 200).Items);

        Assert.Equal(undoId.ToString(), item.Fields["undoneBy"]);
        Assert.Contains("undone", item.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TheHistoryIsReachableThroughTheNormalCommandRouter()
    {
        // `winsight actions` goes through the same router every scan uses.
        var report = Adapters.Run("actions");

        Assert.Equal("actions", report.Tool);
    }
}
