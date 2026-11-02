using System.Text.Json;

using Xunit;

namespace WinSight.Response.Tests;

public sealed class ActionJournalStorageTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-action-storage-").FullName;
    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void ReplacementKeepsChronologicalJsonAndNewestRetention()
    {
        var rows = Enumerable.Range(0, 4).Select(i => new ActionJournalEntry(Guid.NewGuid(),
            ResponseActionKind.AddRule, ResponseOutcome.Succeeded, $"row{i}", DateTimeOffset.UtcNow, true)).ToArray();
        var path = Path.Combine(_root, "history.jsonl");
        Assert.True(ActionJournalStorage.Replace(path, rows.Reverse(), 4096, 3,
            ActionJournalWriteStatus.Updated).Durable);
        Assert.Equal(rows.Skip(1).Select(e => JsonSerializer.Serialize(e)), File.ReadAllLines(path));
        Assert.True(ActionJournalStorage.Preserve(path, path + ".corrupt.jsonl"));
        Assert.Equal(File.ReadAllBytes(path), File.ReadAllBytes(path + ".corrupt.jsonl"));
        Assert.True(ActionJournalStorage.Preserve(path, path + ".corrupt.jsonl"));
        Assert.Equal(File.ReadAllBytes(path), File.ReadAllBytes(path + ".corrupt.jsonl"));
    }

    [Fact]
    public void InvalidOutputLeavesExistingBytesUntouched()
    {
        var path = Path.Combine(_root, "history.jsonl");
        File.WriteAllText(path, "original");
        var invalid = new ActionJournalEntry(Guid.Empty, ResponseActionKind.AddRule,
            ResponseOutcome.Succeeded, "invalid", DateTimeOffset.UtcNow, true);
        Assert.False(ActionJournalStorage.Replace(path, [invalid], 4096, 3,
            ActionJournalWriteStatus.Updated).Durable);
        Assert.Equal("original", File.ReadAllText(path));
    }
}
