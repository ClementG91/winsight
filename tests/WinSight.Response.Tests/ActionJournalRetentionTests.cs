using System.Diagnostics;
using System.Text;
using System.Text.Json;

using Xunit;

namespace WinSight.Response.Tests;

public sealed class ActionJournalRetentionTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-action-retention-").FullName;
    private string PathName => Path.Combine(_root, "history.jsonl");
    public void Dispose() => Directory.Delete(_root, recursive: true);
    private static ActionJournalEntry Entry() => new(Guid.NewGuid(), ResponseActionKind.AddRule,
        ResponseOutcome.Succeeded, "target", DateTimeOffset.UtcNow, true);

    [Fact]
    public void RotationNeverSilentlyDiscardsCorruptEvidence()
    {
        var original = "{ corrupt evidence\n" + string.Concat(Enumerable.Repeat(
            JsonSerializer.Serialize(Entry()) + "\n", 10_000));
        File.WriteAllText(PathName, original, new UTF8Encoding(false));
        var newest = Entry();
        var journal = new ActionJournal(PathName);
        Assert.Equal(ActionJournalWriteStatus.Rotated, journal.TryAppendWithStatus(newest).Status);
        var archive = PathName + ".corrupt.jsonl";
        Assert.Equal(original, File.ReadAllText(archive));
        Assert.InRange(File.ReadAllLines(PathName).Length, 1, 5000);
        Assert.InRange(new FileInfo(PathName).Length, 1, 8 * 1024 * 1024);
        Assert.Equal(newest.ActionId, journal.Read(1)[0].ActionId);
    }

    [Fact]
    public void AnOversizedExistingFilePreservesItsBoundedTailAndReportsPrefixDiscard()
    {
        File.WriteAllText(PathName, new string('x', 20 * 1024 * 1024));
        var length = new FileInfo(PathName).Length;
        var journal = new ActionJournal(PathName);
        Assert.True(journal.TryAppend(Entry()));
        Assert.InRange(new FileInfo(PathName).Length, 1, 8 * 1024 * 1024);
        Assert.Equal(16 * 1024 * 1024, new FileInfo(journal.RecoveryEvidencePath).Length);
        Assert.All(File.ReadAllBytes(journal.RecoveryEvidencePath), b => Assert.Equal((byte)'x', b));
        var discarded = typeof(ActionJournalSnapshot).GetProperty("DiscardedJournalPrefixBytes");
        Assert.NotNull(discarded);
        Assert.Equal(length - 16 * 1024 * 1024, Convert.ToInt64(discarded.GetValue(journal.ReadWithCoverage())));
    }

    [Fact]
    public void ASecondDamagedTailRemainsWritableWithoutOverwritingEarlierEvidence()
    {
        File.WriteAllText(PathName, "{ second corruption\n");
        File.WriteAllText(PathName + ".corrupt.jsonl", "original evidence");
        Assert.True(new ActionJournal(PathName).TryAppend(Entry()));
        Assert.StartsWith("{ second corruption\n", File.ReadAllText(PathName), StringComparison.Ordinal);
        Assert.Equal("original evidence", File.ReadAllText(PathName + ".corrupt.jsonl"));
    }

}
