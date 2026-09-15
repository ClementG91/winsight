using System.Text;

using Xunit;

namespace WinSight.Response.Tests;

public sealed class ActionJournalAndQuarantineTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("winsight-response-store-").FullName;
    private static readonly DateTimeOffset T0 = new(2026, 9, 14, 12, 0, 0, TimeSpan.Zero);

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private ActionJournal Journal() => new(Path.Combine(_directory, "journal.jsonl"));

    private static ActionJournalEntry Entry(Guid id, ResponseActionKind kind = ResponseActionKind.SuspendProcess) =>
        new(id, kind, ResponseOutcome.Succeeded, "target", T0, Reversible: true);

    [Fact]
    public void EntriesAppendAndReadNewestFirst()
    {
        var journal = Journal();
        var first = Guid.NewGuid();
        var second = Guid.NewGuid();
        Assert.True(journal.TryAppend(Entry(first)));
        Assert.True(journal.TryAppend(Entry(second, ResponseActionKind.TerminateProcess)));

        var read = journal.Read();
        Assert.Equal(second, read[0].ActionId);
        Assert.Equal(first, read[1].ActionId);
    }

    [Fact]
    public void MarkUndoneLinksTheReversal()
    {
        var journal = Journal();
        var actionId = Guid.NewGuid();
        var undoId = Guid.NewGuid();
        journal.TryAppend(Entry(actionId));

        journal.MarkUndone(actionId, undoId);

        Assert.Equal(undoId, journal.Read().Single(e => e.ActionId == actionId).UndoneByActionId);
    }

    [Fact]
    public void ACorruptLineIsSkippedNotFatal()
    {
        var path = Path.Combine(_directory, "journal.jsonl");
        File.WriteAllText(path, "{ not json\n");
        var journal = new ActionJournal(path);
        journal.TryAppend(Entry(Guid.NewGuid()));

        Assert.Single(journal.Read());
    }

    [Fact]
    public void AFailedAppendToAnUnusableTargetReturnsFalse()
    {
        Assert.False(new ActionJournal("\0:\\bad<>path\\journal.jsonl").TryAppend(Entry(Guid.NewGuid())));
    }

    [Fact]
    public void QuarantineStoresAndReturnsTheVerifiedPayload()
    {
        var quarantine = new Quarantine(Path.Combine(_directory, "quarantine"));
        var payload = Encoding.UTF8.GetBytes("original value data");

        var item = quarantine.Store(QuarantineItemKind.RegistryValue,
            @"HKCU\Software\...\Run\Updater", "Updater", Guid.NewGuid(), payload, T0);

        Assert.NotNull(item);
        Assert.Equal(payload, quarantine.ReadPayload(item!));
        Assert.Equal(item!.Id, Assert.Single(quarantine.List()).Id);
    }

    [Fact]
    public void ATamperedPayloadFailsTheHashCheck()
    {
        var root = Path.Combine(_directory, "quarantine");
        var quarantine = new Quarantine(root);
        var item = quarantine.Store(QuarantineItemKind.File, @"C:\Startup\x.lnk", "x.lnk",
            Guid.NewGuid(), Encoding.UTF8.GetBytes("payload"), T0)!;

        File.WriteAllBytes(Path.Combine(root, $"{item.Id:N}.bin"), Encoding.UTF8.GetBytes("tampered"));

        Assert.Null(quarantine.ReadPayload(item));
    }

    [Fact]
    public void RemoveDeletesBothManifestAndPayload()
    {
        var root = Path.Combine(_directory, "quarantine");
        var quarantine = new Quarantine(root);
        var item = quarantine.Store(QuarantineItemKind.File, @"C:\Startup\x.lnk", "x.lnk",
            Guid.NewGuid(), Encoding.UTF8.GetBytes("payload"), T0)!;

        quarantine.Remove(item.Id);

        Assert.Empty(quarantine.List());
        Assert.Null(quarantine.ReadPayload(item));
    }
}
