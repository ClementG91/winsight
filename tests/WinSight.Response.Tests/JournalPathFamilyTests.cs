using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Xunit;

namespace WinSight.Response.Tests;

public sealed class JournalPathFamilyTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-path-family-").FullName;
    public void Dispose() => Directory.Delete(_root, recursive: true);
    private static ActionJournalEntry Entry() => new(Guid.NewGuid(), ResponseActionKind.AddRule,
        ResponseOutcome.Succeeded, "existing history", DateTimeOffset.UtcNow, true);

    private string JournalPath(int units, bool supplementary = false) => Path.Combine(_root,
        supplementary ? string.Concat(Enumerable.Repeat("\U0001F512", 100)) + new string('j', units - 200)
            : new string('j', units));

    [Theory]
    [InlineData(219, false, false)]
    [InlineData(219, false, true)]
    [InlineData(245, false, false)]
    [InlineData(245, false, true)]
    [InlineData(255, false, false)]
    [InlineData(255, false, true)]
    [InlineData(219, true, false)]
    [InlineData(219, true, true)]
    public void UnsupportedJournalFamilyRefusesEveryWriteBeforeMutation(int units, bool supplementary, bool existing)
    {
        var path = JournalPath(units, supplementary);
        Assert.Equal(units, Path.GetFileName(path).Length);
        var entry = Entry();
        if (existing)
        {
            File.WriteAllText(path, JsonSerializer.Serialize(entry) + "\n", new UTF8Encoding(false));
        }
        var before = Directory.GetFiles(_root).ToDictionary(p => p, File.ReadAllBytes);
        var journal = new ActionJournal(path);
        var append = journal.TryAppendWithStatus(Entry());
        Assert.Equal("PathTooLong", append.Status.ToString());
        Assert.False(append.Durable);
        Assert.Contains("218", append.Detail, StringComparison.Ordinal);
        Assert.Equal("PathTooLong", journal.TryMarkUndone(entry.ActionId, Guid.NewGuid()).Status.ToString());
        Assert.Equal(before.Keys.Order(), Directory.GetFiles(_root).Order());
        Assert.All(before, item => Assert.Equal(item.Value, File.ReadAllBytes(item.Key)));
    }

    [Theory]
    [InlineData(219)]
    [InlineData(255)]
    public void MissingParentIsNotCreatedForAnUnsupportedFamily(int units)
    {
        var parent = Path.Combine(_root, "not-created");
        var journal = new ActionJournal(Path.Combine(parent, new string('j', units)));
        Assert.Equal("PathTooLong", journal.TryAppendWithStatus(Entry()).Status.ToString());
        Assert.Equal("PathTooLong", journal.TryMarkUndone(Guid.NewGuid(), Guid.NewGuid()).Status.ToString());
        Assert.False(Directory.Exists(parent));
        var snapshot = journal.ReadWithCoverage();
        Assert.False(snapshot.Unreadable);
        Assert.Empty(snapshot.Entries);
        Assert.Equal("PathTooLong", PathFailure(snapshot));
        Assert.False(Directory.Exists(parent));
    }

    [Theory]
    [InlineData(219)]
    [InlineData(239)]
    [InlineData(240)]
    [InlineData(241)]
    [InlineData(245)]
    [InlineData(251)]
    [InlineData(255)]
    public void ExistingLongNameRemainsReadableWithoutInventingLoss(int units)
    {
        var path = JournalPath(units);
        var entry = Entry();
        File.WriteAllText(path, JsonSerializer.Serialize(entry) + "\n", new UTF8Encoding(false));
        if (units <= 241)
        {
            File.WriteAllText(path + ".evidence.json", JsonSerializer.Serialize(new
            {
                Version = 1,
                DiscardedBytes = 10L,
                DiscardedFiles = 2L,
                LossReason = "evidence-budget",
                PriorCountersUnknown = false,
                NextSlot = 0,
                PendingSlot = -1,
                PendingBytes = 0L,
                PendingSha256 = (string?)null,
            }));
        }
        if (units <= 239)
        {
            File.WriteAllText(path + ".corrupt.3.jsonl", "real prior evidence");
        }
        var before = Directory.GetFiles(_root).ToDictionary(p => p, File.ReadAllBytes);
        var snapshot = new ActionJournal(path).ReadWithCoverage();
        Assert.False(snapshot.Unreadable);
        Assert.Equal(entry.ActionId, Assert.Single(snapshot.Entries).ActionId);
        Assert.Equal("PathTooLong", PathFailure(snapshot));
        Assert.Null(typeof(ActionJournalSnapshot).GetProperty("LockFailure")?.GetValue(snapshot));
        Assert.False(snapshot.EvidenceUnavailable);
        Assert.False(snapshot.EvidenceRecoveryPending);
        Assert.Equal(0, snapshot.DiscardedMetadataBytes);
        Assert.Equal(0, snapshot.DiscardedJournalPrefixBytes);
        Assert.Equal(units <= 241 ? 10 : 0, snapshot.DiscardedEvidenceBytes);
        Assert.Equal(units <= 241 ? 2 : 0, snapshot.DiscardedEvidenceFiles);
        Assert.Equal(units <= 239, snapshot.EvidencePreserved);
        Assert.Equal(units > 239, snapshot.EvidenceCountersUnknown);
        Assert.Equal(before.Keys.Order(), Directory.GetFiles(_root).Order());
        Assert.All(before, item => Assert.Equal(item.Value, File.ReadAllBytes(item.Key)));
    }

    [Fact]
    public void FullSupportedBoundaryPreservesAllFourDistinctArchivesAndUndo()
    {
        var path = JournalPath(218, supplementary: true);
        var journal = new ActionJournal(path);
        var previous = Entry();
        for (var slot = 0; slot < 4; slot++)
        {
            var source = $"{{ distinct malformed {slot}\n" + string.Concat(Enumerable.Repeat(
                JsonSerializer.Serialize(previous) + "\n", 10_000));
            File.WriteAllText(path, source, new UTF8Encoding(false));
            previous = Entry();
            Assert.Equal(ActionJournalWriteStatus.Rotated, journal.TryAppendWithStatus(previous).Status);
            var archive = slot == 0 ? path + ".corrupt.jsonl" : path + $".corrupt.{slot}.jsonl";
            Assert.Equal(Encoding.UTF8.GetBytes(source), File.ReadAllBytes(archive));
        }
        var undo = Guid.NewGuid();
        Assert.Equal(ActionJournalWriteStatus.Updated, journal.TryMarkUndone(previous.ActionId, undo).Status);
        var snapshot = journal.ReadWithCoverage();
        Assert.Equal(undo, Assert.Single(snapshot.Entries, entry => entry.ActionId == previous.ActionId).UndoneByActionId);
        Assert.Null(PathFailure(snapshot));
        Assert.False(snapshot.Unreadable);
        Assert.DoesNotContain(Directory.GetFiles(_root), p => p.EndsWith(".winsight-journal.tmp", StringComparison.Ordinal));
    }

    [Fact]
    public void NormalizedRelativeLeafAndInvalidInputKeepTheirContracts()
    {
        var relative = Path.GetRelativePath(Environment.CurrentDirectory, JournalPath(219));
        var journal = new ActionJournal(relative);
        Assert.Equal("PathTooLong", journal.TryAppendWithStatus(Entry()).Status.ToString());
        Assert.Equal(ActionJournalWriteStatus.InvalidRecord, journal.TryAppendWithStatus(Entry() with { ActionId = Guid.Empty }).Status);
        Assert.Equal(ActionJournalWriteStatus.InvalidRecord, journal.TryMarkUndone(Guid.Empty, Guid.NewGuid()).Status);
        Assert.Empty(Directory.GetFiles(_root));
    }

    [Fact]
    public void LongNameReadDoesNotBypassAnExistingDataWriter()
    {
        var path = JournalPath(255);
        File.WriteAllText(path, JsonSerializer.Serialize(Entry()) + "\n");
        using var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
        var snapshot = new ActionJournal(path).ReadWithCoverage();
        Assert.True(snapshot.Unreadable);
        Assert.Empty(snapshot.Entries);
        Assert.Equal("PathTooLong", PathFailure(snapshot));
        Assert.Null(typeof(ActionJournalSnapshot).GetProperty("LockFailure")?.GetValue(snapshot));
        Assert.Single(Directory.GetFiles(_root));
    }

    [Fact]
    public void LongNameReadKeepsPhysicalByteAndMalformedCoverage()
    {
        var path = JournalPath(255);
        File.WriteAllText(path, new string('x', 17 * 1024 * 1024) + "\n{bad}\n");
        var snapshot = new ActionJournal(path).ReadWithCoverage();
        Assert.False(snapshot.Unreadable);
        Assert.True(snapshot.LimitReached);
        Assert.True(snapshot.MalformedEntries > 0);
        Assert.InRange(snapshot.BytesRead, 1, 16 * 1024 * 1024);
        Assert.True(snapshot.RecoveryRequired);
        Assert.Equal("PathTooLong", PathFailure(snapshot));
        Assert.Equal(17 * 1024 * 1024 + 7, new FileInfo(path).Length);
        Assert.Single(Directory.GetFiles(_root));
    }

    [Fact]
    public void LongNameReadDoesNotTreatDataDenialAsAbsence()
    {
        var path = JournalPath(255);
        File.WriteAllText(path, JsonSerializer.Serialize(Entry()) + "\n");
        var file = new FileInfo(path);
        var original = file.GetAccessControl().GetSecurityDescriptorBinaryForm();
        var denied = file.GetAccessControl();
        denied.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!,
            FileSystemRights.ReadData, AccessControlType.Deny));
        try
        {
            file.SetAccessControl(denied);
            var snapshot = new ActionJournal(path).ReadWithCoverage();
            Assert.True(snapshot.Unreadable);
            Assert.Empty(snapshot.Entries);
            Assert.Equal("PathTooLong", PathFailure(snapshot));
            Assert.Null(typeof(ActionJournalSnapshot).GetProperty("LockFailure")?.GetValue(snapshot));
            Assert.Single(Directory.GetFiles(_root));
        }
        finally
        {
            var restored = new FileSecurity();
            restored.SetSecurityDescriptorBinaryForm(original, AccessControlSections.Access);
            file.SetAccessControl(restored);
        }
    }

    [Fact]
    public void LongDirectoryCannotMasqueradeAsAnEmptyJournal()
    {
        var path = JournalPath(255);
        Directory.CreateDirectory(path);
        var snapshot = new ActionJournal(path).ReadWithCoverage();
        Assert.True(snapshot.Unreadable);
        Assert.Empty(snapshot.Entries);
        Assert.Equal("PathTooLong", PathFailure(snapshot));
        Assert.Empty(Directory.GetFiles(_root));
        Assert.Single(Directory.GetDirectories(_root));
    }

    private static string? PathFailure(ActionJournalSnapshot snapshot) =>
        typeof(ActionJournalSnapshot).GetProperty("WritePathFailure")?.GetValue(snapshot)?.ToString();
}
