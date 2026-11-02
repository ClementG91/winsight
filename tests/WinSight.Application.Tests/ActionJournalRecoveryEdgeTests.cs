using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;

using WinSight.Core;
using WinSight.Reporting;
using WinSight.Response;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class ActionJournalRecoveryEdgeTests : IDisposable
{
    private const int Budget = 16 * 1024 * 1024;
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-recovery-edges-").FullName;
    private string PathName => Path.Combine(_root, "history.jsonl");
    private string Archive => PathName + ".corrupt.jsonl";
    private string Metadata => PathName + ".evidence.json";
    public void Dispose() => Directory.Delete(_root, recursive: true);
    private static ActionJournalEntry Entry() => new(Guid.NewGuid(), ResponseActionKind.AddRule,
        ResponseOutcome.AuditPrepared, "target", DateTimeOffset.UtcNow, false, Phase: ActionJournalPhase.Prepared);

    [Fact]
    public void AnOversizedReplacementOfAPendingEvictionVictimNeverDeadEndsRecovery()
    {
        File.WriteAllText(PathName, JsonSerializer.Serialize(Entry()) + "\n");
        File.WriteAllText(Archive, new string('x', 20 * 1024 * 1024));
        File.WriteAllText(Metadata, JsonSerializer.Serialize(new
        {
            Version = 1,
            DiscardedBytes = 0L,
            DiscardedFiles = 0L,
            LossReason = "",
            PriorCountersUnknown = false,
            NextSlot = 0,
            PendingSlot = 0,
            PendingBytes = 9L,
            PendingSha256 = Convert.ToHexString(SHA256.HashData("evidence0"u8)),
        }));
        var journal = new ActionJournal(PathName);
        Assert.True(journal.TryAppendWithStatus(Entry()).Durable);
        Assert.Equal(Budget, new FileInfo(Archive).Length);
        Assert.Equal(Enumerable.Repeat((byte)'x', Budget), File.ReadAllBytes(Archive));
        var snapshot = journal.ReadWithCoverage();
        Assert.True(snapshot.EvidenceCountersUnknown);
        Assert.Equal(4 * 1024 * 1024, snapshot.DiscardedEvidenceBytes);
        Assert.Equal(0, snapshot.DiscardedEvidenceFiles);
        Assert.False(snapshot.EvidenceRecoveryPending);
        Assert.True(journal.TryAppendWithStatus(Entry()).Durable);
        Assert.Equal(snapshot.DiscardedEvidenceBytes, journal.ReadWithCoverage().DiscardedEvidenceBytes);
    }

    [Theory]
    [InlineData("oversized-archive")]
    [InlineData("directory-archive")]
    [InlineData("directory-metadata")]
    public void HistoryReportsEvidenceThatBlocksOrRequiresRecoveryBeforeWriting(string state)
    {
        File.WriteAllText(PathName, JsonSerializer.Serialize(Entry()) + "\n");
        if (state == "oversized-archive")
        {
            File.WriteAllText(Archive, new string('x', Budget + 1));
        }
        else
        {
            Directory.CreateDirectory(state == "directory-archive" ? Archive : Metadata);
        }
        var files = Directory.GetFiles(_root).ToDictionary(path => path, File.ReadAllBytes);
        var directories = Directory.GetDirectories(_root);
        var snapshot = new ActionJournal(PathName).ReadWithCoverage();
        Assert.True(snapshot.RecoveryRequired);
        var report = Adapters.Actions(PathName, 200);
        Assert.True(report.NotableCount > 0);
        Assert.Contains("recovery", report.Summary, StringComparison.OrdinalIgnoreCase);
        using var text = new StringWriter();
        ReportRenderer.RenderText(report, text);
        Assert.Contains("evidence", text.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(directories, Directory.GetDirectories(_root));
        Assert.Equal(files.Keys.Order(), Directory.GetFiles(_root).Order());
        Assert.All(files, pair => Assert.Equal(pair.Value, File.ReadAllBytes(pair.Key)));
    }

    [Fact]
    public void PendingArchiveTrimIsVisibleEvenWhenItsAtomicReplacementIsBlocked()
    {
        File.WriteAllText(PathName, JsonSerializer.Serialize(Entry()) + "\n");
        File.WriteAllText(Archive, new string('x', 20 * 1024 * 1024));
        var main = File.ReadAllBytes(PathName);
        using (var locked = new FileStream(Archive, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            var journal = new ActionJournal(PathName);
            Assert.False(journal.TryAppendWithStatus(Entry()).Durable);
            Assert.Equal(main, File.ReadAllBytes(PathName));
            Assert.Equal(20 * 1024 * 1024, locked.Length);
            var snapshot = journal.ReadWithCoverage();
            Assert.True(snapshot.EvidenceRecoveryPending);
            var property = typeof(ActionJournalSnapshot).GetProperty("PendingEvidencePrefixDiscardBytes");
            Assert.NotNull(property);
            Assert.Equal(4 * 1024 * 1024L, property.GetValue(snapshot));
            using var text = new StringWriter();
            ReportRenderer.RenderText(Adapters.Actions(PathName, 200), text);
            Assert.Contains("pending evidence prefix bytes: 4194304", text.ToString(), StringComparison.Ordinal);
            Assert.Contains("recovery pending: true", text.ToString(), StringComparison.Ordinal);
        }
        Assert.True(new ActionJournal(PathName).TryAppendWithStatus(Entry()).Durable);
        Assert.False(new ActionJournal(PathName).ReadWithCoverage().EvidenceRecoveryPending);
    }

    [Fact]
    public void AReadDenialAfterPublicationNeverDowngradesTheDurableIntent()
    {
        File.WriteAllText(PathName, new string('x', 20 * 1024 * 1024));
        File.WriteAllText(Archive, new string('x', Budget));
        File.WriteAllText(Metadata, JsonSerializer.Serialize(new
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
        var directory = new DirectoryInfo(_root);
        var originalDirectory = directory.GetAccessControl();
        var originals = Directory.GetFiles(_root).ToDictionary(path => path, path => new FileInfo(path).GetAccessControl());
        var currentUser = WindowsIdentity.GetCurrent().User!;
        try
        {
            // Existing source, proof and ledger remain readable; only newly created staging and
            // published replacements inherit the data-read denial. Attribute acquisition still works.
            foreach (var path in originals.Keys)
            {
                var security = new FileInfo(path).GetAccessControl();
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: true);
                new FileInfo(path).SetAccessControl(security);
            }
            var denied = directory.GetAccessControl();
            denied.AddAccessRule(new FileSystemAccessRule(currentUser, FileSystemRights.ReadData,
                InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly, AccessControlType.Deny));
            directory.SetAccessControl(denied);
            var attempted = Entry();
            var journal = new ActionJournal(PathName);
            var result = journal.TryAppendWithStatus(attempted);
            Assert.True(result.Durable, $"Published intent was incorrectly reported as {result.Status}.");
            Assert.InRange(new FileInfo(PathName).Length, 1, Budget);
            using (var observed = AutomaticFileAccess.TryAcquire(PathName))
            {
                Assert.NotNull(observed);
                Assert.Throws<IOException>(() => observed.OpenRead());
            }
            RestoreAcl();
            Assert.Equal(attempted.ActionId, Assert.Single(journal.Read()).ActionId);
            Assert.True(journal.ReadWithCoverage().EvidenceRecoveryPending);
            Assert.True(journal.TryAppendWithStatus(Entry()).Durable);
            Assert.False(journal.ReadWithCoverage().EvidenceRecoveryPending);
            Assert.Equal(4 * 1024 * 1024, journal.ReadWithCoverage().DiscardedJournalPrefixBytes);
        }
        finally
        {
            RestoreAcl();
        }

        void RestoreAcl()
        {
            var directorySecurity = new DirectorySecurity();
            directorySecurity.SetSecurityDescriptorBinaryForm(originalDirectory.GetSecurityDescriptorBinaryForm(), AccessControlSections.Access);
            directory.SetAccessControl(directorySecurity);
            foreach (var pair in originals)
            {
                if (File.Exists(pair.Key))
                {
                    var fileSecurity = new FileSecurity();
                    fileSecurity.SetSecurityDescriptorBinaryForm(pair.Value.GetSecurityDescriptorBinaryForm(), AccessControlSections.Access);
                    new FileInfo(pair.Key).SetAccessControl(fileSecurity);
                }
            }
        }
    }
}
