using WinSight.Core;

using Xunit;

namespace WinSight.Response.Tests;

public sealed class JournalStagingOwnershipTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-staging-owner-").FullName;
    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void AReplacementNeverDeletesAnotherJournalAtItsStagingPath()
    {
        var path = Path.Combine(_root, "first.jsonl");
        var secondPath = path + ".winsight-journal.tmp";
        var first = new ActionJournal(path);
        var second = new ActionJournal(secondPath);
        var entry = Entry();
        Assert.True(first.TryAppend(entry));
        Assert.True(second.TryAppend(Entry()));
        var before = Directory.GetFiles(_root).ToDictionary(file => file, File.ReadAllBytes);

        var result = first.TryMarkUndone(entry.ActionId, Guid.NewGuid());

        Assert.Equal(ActionJournalWriteStatus.RotationFailed, result.Status);
        Assert.False(result.Durable);
        Assert.Equal(before.Keys.Order(), Directory.GetFiles(_root).Order());
        Assert.All(before, pair => Assert.Equal(pair.Value, File.ReadAllBytes(pair.Key)));
        Assert.Equal(entry.ActionId, Assert.Single(first.Read()).ActionId);
        Assert.Null(Assert.Single(first.Read()).UndoneByActionId);
        Assert.Single(second.Read());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AtomicPublicationNeverDeletesUnownedStaging(bool copyTail)
    {
        var source = Path.Combine(_root, "source.jsonl");
        var destination = Path.Combine(_root, "destination.jsonl");
        File.WriteAllText(source, "source evidence");
        File.WriteAllText(destination, "original destination");
        File.WriteAllText(destination + ".winsight-journal.tmp", "unrelated operator file");
        var before = Directory.GetFiles(_root).ToDictionary(file => file, File.ReadAllBytes);

        var succeeded = copyTail
            ? AutomaticFileAccess.TryCopyTailAtomic(source, destination, 1024, replaceExisting: true)
            : AutomaticFileAccess.TryWriteAtomicBounded(destination, "replacement"u8);

        Assert.False(succeeded);
        Assert.Equal(before.Keys.Order(), Directory.GetFiles(_root).Order());
        Assert.All(before, pair => Assert.Equal(pair.Value, File.ReadAllBytes(pair.Key)));
    }

    private static ActionJournalEntry Entry() => new(Guid.NewGuid(), ResponseActionKind.AddRule,
        ResponseOutcome.Succeeded, "owned-action", DateTimeOffset.UtcNow, true);
}
