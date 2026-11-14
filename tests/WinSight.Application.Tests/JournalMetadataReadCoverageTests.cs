using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

using WinSight.Reporting;
using WinSight.Response;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class JournalMetadataReadCoverageTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-metadata-coverage-").FullName;
    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Theory]
    [InlineData("directory")]
    [InlineData("attributes-denied")]
    public void MetadataCoverageFollowsEffectiveDataAvailability(string kind)
    {
        var path = Path.Combine(_root, "history.jsonl");
        var metadataPath = path + ".evidence.json";
        var journal = new ActionJournal(path);
        Assert.True(journal.TryAppend(new ActionJournalEntry(Guid.NewGuid(), ResponseActionKind.AddRule,
            ResponseOutcome.Succeeded, "readable-action", DateTimeOffset.UtcNow, true)));
        FileInfo? metadata = null;
        FileSecurity? original = null;
        if (kind == "directory")
        {
            Directory.CreateDirectory(metadataPath);
        }
        else
        {
            File.WriteAllText(metadataPath, "{ unreadable metadata");
            metadata = new FileInfo(metadataPath);
            original = metadata.GetAccessControl();
            var denied = metadata.GetAccessControl();
            denied.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!,
                FileSystemRights.ReadAttributes, AccessControlType.Deny));
            metadata.SetAccessControl(denied);
        }
        try
        {
            var snapshot = journal.ReadWithCoverage();
            Assert.False(snapshot.Unreadable);
            Assert.Single(snapshot.Entries);
            // Windows permits the measured native read with an attribute-only denial. The
            // malformed but readable index is unknown accounting, not unavailable evidence.
            Assert.Equal(kind == "directory", snapshot.EvidenceUnavailable);
            Assert.True(snapshot.EvidenceRecoveryPending);
            Assert.True(snapshot.EvidenceCountersUnknown);
        }
        finally
        {
            if (metadata is not null && original is not null)
            {
                var restored = new FileSecurity();
                restored.SetSecurityDescriptorBinaryForm(original.GetSecurityDescriptorBinaryForm(), AccessControlSections.Access);
                metadata.SetAccessControl(restored);
            }
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DeniedMetadataDoesNotHideReadableJournalEntries(bool malformedMetadata)
    {
        var path = Path.Combine(_root, "history.jsonl");
        var metadataPath = path + ".evidence.json";
        var journal = new ActionJournal(path);
        var entry = new ActionJournalEntry(Guid.NewGuid(), ResponseActionKind.AddRule,
            ResponseOutcome.Succeeded, "readable-action", DateTimeOffset.UtcNow, true);
        Assert.True(journal.TryAppend(entry));
        File.WriteAllText(metadataPath, malformedMetadata ? "{ malformed" : JsonSerializer.Serialize(new
        {
            Version = 1,
            DiscardedBytes = 0L,
            DiscardedFiles = 0L,
            LossReason = "",
            PriorCountersUnknown = false,
            NextSlot = 0,
            PendingSlot = -1,
            PendingBytes = 0L,
            PendingSha256 = (string?)null,
        }));
        var before = Directory.GetFiles(_root).ToDictionary(file => file, File.ReadAllBytes);
        var metadata = new FileInfo(metadataPath);
        var original = metadata.GetAccessControl();
        var denied = metadata.GetAccessControl();
        denied.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!,
            FileSystemRights.ReadData, AccessControlType.Deny));
        try
        {
            metadata.SetAccessControl(denied);
            var snapshot = journal.ReadWithCoverage();
            Assert.False(snapshot.Unreadable);
            Assert.Equal(entry.ActionId, Assert.Single(snapshot.Entries).ActionId);
            Assert.True(snapshot.EvidenceUnavailable);
            Assert.True(snapshot.EvidenceRecoveryPending);
            Assert.True(snapshot.EvidenceCountersUnknown);
            var report = Adapters.Actions(path, 200);
            Assert.Equal(1, report.NotableCount);
            Assert.Equal(Severity.Notable, Assert.Single(report.Items,
                item => item.Fields["kind"] == "actionJournalCoverage").Severity);
            Assert.Equal(entry.ActionId.ToString(), Assert.Single(report.Items,
                item => item.Fields["kind"] == "responseAction").Fields["actionId"]);
            Assert.Contains("incomplete", report.Summary, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("EvidenceRecoveryBlocked", journal.TryAppendWithStatus(entry with { ActionId = Guid.NewGuid() }).Status.ToString());
            Assert.Equal("EvidenceRecoveryBlocked", journal.TryMarkUndone(entry.ActionId, Guid.NewGuid()).Status.ToString());
            Assert.Equal(before.Keys.Order(), Directory.GetFiles(_root).Order());
            Assert.Equal(before[path], File.ReadAllBytes(path));
        }
        finally
        {
            var restored = new FileSecurity();
            restored.SetSecurityDescriptorBinaryForm(original.GetSecurityDescriptorBinaryForm(), AccessControlSections.Access);
            metadata.SetAccessControl(restored);
        }
        Assert.All(before, item => Assert.Equal(item.Value, File.ReadAllBytes(item.Key)));
    }
}
