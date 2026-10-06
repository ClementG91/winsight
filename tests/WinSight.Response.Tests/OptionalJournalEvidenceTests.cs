using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;

using Xunit;

namespace WinSight.Response.Tests;

public sealed class OptionalJournalEvidenceTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-optional-evidence-").FullName;
    private string JournalPath => Path.Combine(_root, "history.jsonl");
    private string Archive => JournalPath + ".corrupt.2.jsonl";
    public void Dispose() => Directory.Delete(_root, recursive: true);
    private static ActionJournalEntry Entry() => new(Guid.NewGuid(), ResponseActionKind.AddRule,
        ResponseOutcome.Succeeded, "target", DateTimeOffset.UtcNow, true);

    [Theory]
    [InlineData("directory")]
    [InlineData("junction")]
    [InlineData("access-denied")]
    public async Task AnUnusableArchiveDoesNotBlockHealthyAppendOrUndo(string kind)
    {
        var original = Entry();
        var journal = new ActionJournal(JournalPath);
        Assert.True(journal.TryAppend(original));
        using var blocker = await BlockArchive(kind);
        Assert.Equal(ActionJournalWriteStatus.Appended, journal.TryAppendWithStatus(Entry()).Status);
        var undo = Guid.NewGuid();
        Assert.Equal(ActionJournalWriteStatus.Updated, journal.TryMarkUndone(original.ActionId, undo).Status);
        var snapshot = journal.ReadWithCoverage();
        Assert.False(snapshot.Unreadable);
        Assert.True(snapshot.EvidenceUnavailable);
        Assert.Equal(undo, Assert.Single(snapshot.Entries, x => x.ActionId == original.ActionId).UndoneByActionId);
        Assert.False(File.Exists(JournalPath + ".corrupt.jsonl"));
        Assert.False(File.Exists(JournalPath + ".corrupt.1.jsonl"));
        Assert.False(File.Exists(JournalPath + ".corrupt.3.jsonl"));
        if (kind == "junction")
        {
            Assert.Empty(Directory.GetFileSystemEntries(Path.Combine(_root, "junction-target")));
        }
    }

    [Theory]
    [InlineData("directory")]
    [InlineData("junction")]
    [InlineData("access-denied")]
    public async Task RequiredPreservationRefusesAnUnassessableArchiveWithoutChangingTheJournal(string kind)
    {
        var original = "{ corrupt evidence\n" + string.Concat(Enumerable.Repeat(JsonSerializer.Serialize(Entry()) + "\n", 10_000));
        File.WriteAllText(JournalPath, original);
        using var blocker = await BlockArchive(kind);
        var journal = new ActionJournal(JournalPath);
        Assert.Equal(ActionJournalWriteStatus.EvidencePreservationFailed, journal.TryAppendWithStatus(Entry()).Status);
        Assert.Equal(original, File.ReadAllText(JournalPath));
        Assert.True(journal.ReadWithCoverage().EvidenceUnavailable);
        Assert.False(File.Exists(JournalPath + ".corrupt.jsonl"));
        Assert.False(File.Exists(JournalPath + ".corrupt.1.jsonl"));
        Assert.False(File.Exists(JournalPath + ".corrupt.3.jsonl"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UnresolvedIntentOrUnavailableMetadataHasAPreciseRecoveryBlock(bool unavailable)
    {
        var entry = Entry();
        var original = JsonSerializer.Serialize(entry) + "\n";
        File.WriteAllText(JournalPath, original);
        if (unavailable)
        {
            Directory.CreateDirectory(JournalPath + ".evidence.json");
        }
        else
        {
            Directory.CreateDirectory(Archive);
            File.WriteAllText(JournalPath + ".evidence.json", JsonSerializer.Serialize(new
            {
                Version = 1,
                DiscardedBytes = 0L,
                DiscardedFiles = 0L,
                LossReason = "",
                PriorCountersUnknown = false,
                NextSlot = 0,
                PendingSlot = 2,
                PendingBytes = 8L,
                PendingSha256 = Convert.ToHexString(SHA256.HashData("evidence"u8)),
            }));
        }
        var journal = new ActionJournal(JournalPath);
        var append = journal.TryAppendWithStatus(Entry());
        Assert.Equal("EvidenceRecoveryBlocked", append.Status.ToString());
        Assert.Contains("pending", append.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("EvidenceRecoveryBlocked", journal.TryMarkUndone(entry.ActionId, Guid.NewGuid()).Status.ToString());
        Assert.Equal(original, File.ReadAllText(JournalPath));
        Assert.True(journal.ReadWithCoverage().EvidenceRecoveryPending);
    }

    private async Task<IDisposable> BlockArchive(string kind)
    {
        if (kind == "access-denied")
        {
            File.WriteAllText(Archive, new string('x', 16 * 1024 * 1024 + 1));
            var file = new FileInfo(Archive);
            var original = file.GetAccessControl();
            var denied = file.GetAccessControl();
            denied.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!,
                FileSystemRights.ReadData, AccessControlType.Deny));
            file.SetAccessControl(denied);
            return new Cleanup(() =>
            {
                var restored = new FileSecurity();
                restored.SetSecurityDescriptorBinaryForm(original.GetSecurityDescriptorBinaryForm(), AccessControlSections.Access);
                file.SetAccessControl(restored);
            });
        }
        if (kind == "directory")
        {
            Directory.CreateDirectory(Archive);
            return new Cleanup(() => { });
        }
        var target = Directory.CreateDirectory(Path.Combine(_root, "junction-target")).FullName;
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("ComSpec")!)
        {
            Arguments = $"/d /c mklink /J \"{Archive}\" \"{target}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var child = Process.Start(start)!;
        try
        {
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
            Assert.Equal(0, child.ExitCode);
            Assert.True(File.GetAttributes(Archive).HasFlag(FileAttributes.ReparsePoint));
        }
        finally
        {
            if (!child.HasExited)
            {
                child.Kill(entireProcessTree: true);
                child.WaitForExit(5000);
            }
        }
        return new Cleanup(() => Directory.Delete(Archive));
    }

    private sealed class Cleanup(Action action) : IDisposable
    {
        public void Dispose() => action();
    }
}
