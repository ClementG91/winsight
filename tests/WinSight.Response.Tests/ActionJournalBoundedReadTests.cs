using System.Text;
using System.Text.Json;

using Xunit;

namespace WinSight.Response.Tests;

public sealed class ActionJournalBoundedReadTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-action-tail-").FullName;
    private string PathName => Path.Combine(_root, "history.jsonl");
    public void Dispose() => Directory.Delete(_root, recursive: true);

    private static ActionJournalEntry Entry(string target = "target") => new(Guid.NewGuid(),
        ResponseActionKind.AddRule, ResponseOutcome.Succeeded, target, DateTimeOffset.UtcNow, true);

    [Fact]
    public void APageReadsTheTailInsteadOfTheLargePrefix()
    {
        var entry = Entry("évidence 😀");
        File.WriteAllText(PathName, new string('x', 20 * 1024 * 1024) + "\n"
            + JsonSerializer.Serialize(entry) + "\n", new UTF8Encoding(false));
        var read = new ActionJournal(PathName).ReadWithCoverage(1);
        Assert.Equal(entry, Assert.Single(read.Entries));
        Assert.InRange(read.BytesRead, 1, 8192);
        Assert.Equal(1, read.LinesScanned);
        Assert.False(read.Unreadable);
    }

    [Theory]
    [InlineData(16 * 1024)]
    [InlineData(16 * 1024 * 1024 + 1)]
    public void InvalidLinesAreBoundedBeforeAllocation(int length)
    {
        File.WriteAllText(PathName, new string('x', length), new UTF8Encoding(false));
        var read = new ActionJournal(PathName).ReadWithCoverage();
        Assert.Empty(read.Entries);
        Assert.InRange(read.BytesRead, 1, 16 * 1024 * 1024);
        Assert.True(read.MalformedEntries > 0 || read.LimitReached);
    }

    [Fact]
    public void BlankAndCorruptLinesCountTowardThePhysicalBudget()
    {
        File.WriteAllText(PathName, string.Concat(Enumerable.Repeat("bad\n\n", 10_001)));
        var read = new ActionJournal(PathName).ReadWithCoverage();
        Assert.Empty(read.Entries);
        Assert.Equal(10_000, read.LinesScanned);
        Assert.True(read.LimitReached);
        Assert.True(read.MalformedEntries > 0);
    }

    [Fact]
    public void TheLatestPhysicalRecordWinsAcrossBlocksAndLineEndings()
    {
        var entry = Entry(new string('x', 9000));
        var completed = entry with { Outcome = ResponseOutcome.Failed };
        File.WriteAllText(PathName, JsonSerializer.Serialize(entry) + "\r\n"
            + JsonSerializer.Serialize(completed), new UTF8Encoding(true));
        Assert.Equal(completed, Assert.Single(new ActionJournal(PathName).Read(0)));
    }

    [Fact]
    public void InvalidRecordShapesAreCorruptionRatherThanSuccess()
    {
        File.WriteAllText(PathName, "{}\nnull\n" + JsonSerializer.Serialize(Entry() with { Target = null! }));
        var read = new ActionJournal(PathName).ReadWithCoverage();
        Assert.Empty(read.Entries);
        Assert.Equal(3, read.MalformedEntries);
    }

    [Fact]
    public void OversizedLabelsAreBoundedWithoutRefusingTheAction()
    {
        Assert.True(new ActionJournal(PathName).TryAppend(Entry(new string('x', 16 * 1024))));
        var entry = Assert.Single(new ActionJournal(PathName).Read());
        Assert.InRange(entry.Target.Length, 1, 2048);
        Assert.Contains("[truncated sha256:", entry.Target, StringComparison.Ordinal);
        Assert.True(new FileInfo(PathName).Length <= ActionJournalReader.MaxLineBytes);
    }
}
