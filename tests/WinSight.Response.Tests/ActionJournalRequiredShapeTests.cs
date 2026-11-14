using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using Xunit;

namespace WinSight.Response.Tests;

public sealed class ActionJournalRequiredShapeTests
{
    private static ActionJournalEntry Entry() => new(
        Guid.Parse("11111111-1111-1111-1111-111111111111"),
        ResponseActionKind.SuspendProcess, ResponseOutcome.Succeeded, "shape probe",
        DateTimeOffset.Parse("2026-10-04T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture), false);

    private static ActionJournalSnapshot Read(string json)
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json + "\n"));
        return ActionJournalReader.Read(stream, 200);
    }

    [Theory]
    [InlineData(nameof(ActionJournalEntry.ActionId))]
    [InlineData(nameof(ActionJournalEntry.Kind))]
    [InlineData(nameof(ActionJournalEntry.Outcome))]
    [InlineData(nameof(ActionJournalEntry.Target))]
    [InlineData(nameof(ActionJournalEntry.AtUtc))]
    [InlineData(nameof(ActionJournalEntry.Reversible))]
    public void MissingRequiredFieldsAreMalformed(string missing)
    {
        var json = JsonSerializer.SerializeToNode(Entry())!.AsObject();
        Assert.True(json.Remove(missing));
        var result = Read(json.ToJsonString());
        Assert.Empty(result.Entries);
        Assert.Equal(1, result.MalformedEntries);
        Assert.False(result.Unreadable);
    }

    [Fact]
    public void MinimalRecordCannotSynthesizeSuccessfulCompletion()
    {
        var result = Read("""{"ActionId":"11111111-1111-1111-1111-111111111111","Target":"probe missing outcome"}""");
        Assert.Empty(result.Entries);
        Assert.Equal(1, result.MalformedEntries);
    }

    [Fact]
    public void MissingHistoricalOptionalFieldsRetainsCompletedDefault()
    {
        var entry = Entry();
        var json = JsonSerializer.SerializeToNode(entry)!.AsObject();
        Assert.True(json.Remove(nameof(ActionJournalEntry.Phase)));
        Assert.True(json.Remove(nameof(ActionJournalEntry.UndoneByActionId)));
        var result = Read(json.ToJsonString());
        Assert.Equal(entry, Assert.Single(result.Entries));
        Assert.Equal(0, result.MalformedEntries);
    }

    [Fact]
    public void ExplicitZeroEnumAndFalseValuesRemainValid()
    {
        var entry = Entry();
        var result = Read(JsonSerializer.Serialize(entry));
        Assert.Equal(entry, Assert.Single(result.Entries));
        Assert.Equal(0, result.MalformedEntries);
    }
}
