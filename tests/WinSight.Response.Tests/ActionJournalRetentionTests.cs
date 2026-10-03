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
        Assert.True(new ActionJournal(PathName).TryAppend(Entry()));
        var archive = PathName + ".corrupt.jsonl";
        Assert.True(File.ReadAllText(PathName).Contains("{ corrupt evidence", StringComparison.Ordinal)
            || File.Exists(archive) && File.ReadAllText(archive) == original);
    }

    [Fact]
    public void AnOversizedExistingFileIsNotGrownOrDestroyed()
    {
        File.WriteAllText(PathName, new string('x', 20 * 1024 * 1024));
        var length = new FileInfo(PathName).Length;
        Assert.False(new ActionJournal(PathName).TryAppend(Entry()));
        Assert.Equal(length, new FileInfo(PathName).Length);
    }

    [Fact]
    public void CorruptEvidenceCannotBeOverwrittenByASecondRecovery()
    {
        File.WriteAllText(PathName, "{ second corruption\n");
        File.WriteAllText(PathName + ".corrupt.jsonl", "original evidence");
        Assert.False(new ActionJournal(PathName).TryAppend(Entry()));
        Assert.Equal("{ second corruption\n", File.ReadAllText(PathName));
        Assert.Equal("original evidence", File.ReadAllText(PathName + ".corrupt.jsonl"));
    }

}
