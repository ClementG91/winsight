using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using WinSight.Core;
using WinSight.Reporting;
using WinSight.Response;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class LegacyActionJournalRecoveryTests : IDisposable
{
    private const int Budget = 16 * 1024 * 1024;
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-legacy-recovery-").FullName;
    private string PathName => Path.Combine(_root, "history.jsonl");
    public void Dispose() => Directory.Delete(_root, recursive: true);
    private static ActionJournalEntry Entry(string target = "target") => new(Guid.NewGuid(),
        ResponseActionKind.AddRule, ResponseOutcome.Succeeded, target, DateTimeOffset.UtcNow, true);

    [Fact]
    public void LegacyOversizedHistoryMigratesAutomaticallyAndKeepsItsNewestValidTail()
    {
        var newest = CreateLegacyHistory();
        var original = File.ReadAllBytes(PathName);
        var journal = new ActionJournal(PathName);
        var current = Entry();
        Assert.Equal(ActionJournalWriteStatus.Rotated, journal.TryAppendWithStatus(current).Status);
        Assert.InRange(new FileInfo(PathName).Length, 1, 8 * 1024 * 1024);
        Assert.Contains(journal.Read(), row => row.ActionId == newest.ActionId);
        Assert.Equal(current.ActionId, journal.Read(1)[0].ActionId);
        Assert.Equal(original.TakeLast(Budget), File.ReadAllBytes(journal.RecoveryEvidencePath));
        Assert.Equal(original.Length - Budget, SnapshotLong(journal.ReadWithCoverage(), "DiscardedJournalPrefixBytes"));
        Assert.False(journal.ReadWithCoverage().EvidenceCountersUnknown);
    }

    [Fact]
    public void OversizedHistoryNeverReportsHealthyCoverageBeforeMigrationAndReadIsPure()
    {
        _ = CreateLegacyHistory();
        var original = File.ReadAllBytes(PathName);
        var report = Adapters.Actions(PathName, 200);
        Assert.True(report.NotableCount > 0);
        Assert.Contains("recovery", report.Summary, StringComparison.OrdinalIgnoreCase);
        using var text = new StringWriter();
        ReportRenderer.RenderText(report, text);
        Assert.Contains("16 MiB", text.ToString(), StringComparison.Ordinal);
        Assert.Equal(original, File.ReadAllBytes(PathName));
        Assert.Single(Directory.GetFiles(_root));
    }

    [Fact]
    public void FailedLegacyRenameNeverClaimsPrefixLossAndRetryCountsItExactlyOnce()
    {
        _ = CreateLegacyHistory();
        var original = File.ReadAllBytes(PathName);
        var journal = new ActionJournal(PathName);
        using (new FileStream(PathName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            Assert.Equal(ActionJournalWriteStatus.RotationFailed, journal.TryAppendWithStatus(Entry()).Status);
            Assert.Equal(0, SnapshotLong(journal.ReadWithCoverage(), "DiscardedJournalPrefixBytes"));
            Assert.Equal(original.Length - Budget, SnapshotLong(journal.ReadWithCoverage(), "PendingPrefixDiscardBytes"));
            Assert.Equal(original, File.ReadAllBytes(PathName));
        }
        Assert.True(journal.TryAppend(Entry()));
        Assert.Equal(original.Length - Budget, SnapshotLong(journal.ReadWithCoverage(), "DiscardedJournalPrefixBytes"));
        Assert.Equal(0, SnapshotLong(journal.ReadWithCoverage(), "PendingPrefixDiscardBytes"));
        Assert.True(journal.TryAppend(Entry()));
        Assert.Equal(original.Length - Budget, SnapshotLong(journal.ReadWithCoverage(), "DiscardedJournalPrefixBytes"));
    }

    [Fact]
    public void AnOversizedEvidenceSlotIsBoundedWithoutPermanentRefusal()
    {
        var original = Encoding.UTF8.GetBytes(new string('e', 20 * 1024 * 1024));
        File.WriteAllBytes(PathName + ".corrupt.jsonl", original);
        File.WriteAllText(PathName, "{ damaged\n" + new string('\n', 10_000));
        var journal = new ActionJournal(PathName);
        Assert.True(journal.TryAppend(Entry()));
        Assert.Equal(original.TakeLast(Budget), File.ReadAllBytes(journal.RecoveryEvidencePath));
        Assert.Equal(original.Length - Budget, journal.ReadWithCoverage().DiscardedEvidenceBytes);
        Assert.False(journal.ReadWithCoverage().EvidenceCountersUnknown);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SaturatedEvidenceCountersExplicitlyStopClaimingExactAccounting(bool files)
    {
        File.WriteAllText(PathName, "{ damaged\n" + new string('\n', 10_000));
        for (var i = 0; i < 4; i++)
        {
            File.WriteAllText(i == 0 ? PathName + ".corrupt.jsonl" : PathName + $".corrupt.{i}.jsonl", "evidence" + i);
        }
        WriteState(new
        {
            Version = 1,
            DiscardedBytes = files ? 0 : long.MaxValue - 1,
            DiscardedFiles = files ? long.MaxValue : 0,
            LossReason = "",
            PriorCountersUnknown = false,
            NextSlot = 0,
            PendingSlot = -1,
            PendingBytes = 0L,
            PendingSha256 = (string?)null,
        });
        var journal = new ActionJournal(PathName);
        Assert.True(journal.TryAppend(Entry()));
        Assert.True(journal.ReadWithCoverage().EvidenceCountersUnknown);
        Assert.Equal(long.MaxValue, files ? journal.ReadWithCoverage().DiscardedEvidenceFiles : journal.ReadWithCoverage().DiscardedEvidenceBytes);
    }

    [Fact]
    public void CorruptMetadataHasAnExplicitDiscardHashWithABoundedTailScope()
    {
        var metadata = Encoding.UTF8.GetBytes(new string('m', 10 * 1024));
        File.WriteAllBytes(PathName + ".evidence.json", metadata);
        File.WriteAllText(PathName, "{ damaged\n" + new string('\n', 10_000));
        var journal = new ActionJournal(PathName);
        Assert.True(journal.TryAppend(Entry()));
        var snapshot = journal.ReadWithCoverage();
        Assert.True(snapshot.EvidenceCountersUnknown);
        Assert.Equal(metadata.Length, snapshot.DiscardedMetadataBytes);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(metadata.AsSpan(metadata.Length - 8192))),
            typeof(ActionJournalSnapshot).GetProperty("DiscardedMetadataTailSha256")?.GetValue(snapshot));
        using var text = new StringWriter();
        ReportRenderer.RenderText(Adapters.Actions(PathName, 200), text);
        Assert.Contains(metadata.Length.ToString(System.Globalization.CultureInfo.InvariantCulture), text.ToString(), StringComparison.Ordinal);
        Assert.Contains("unknown", text.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, false, true)]
    public void PendingSourceTrimFinalizesAfterAnAlreadyPublishedReplacement(bool unexpected, bool proofMissing, bool mainMissing)
    {
        var original = Encoding.UTF8.GetBytes(new string('x', 20 * 1024 * 1024));
        File.WriteAllBytes(PathName, original);
        uint volume;
        ulong index;
        using (var lease = AutomaticFileAccess.TryAcquire(PathName)!)
        {
            volume = lease.Identity.VolumeSerialNumber;
            index = lease.Identity.FileIndex;
        }
        File.WriteAllBytes(PathName + ".corrupt.jsonl", original.TakeLast(Budget).ToArray());
        var replacement = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(Entry()) + "\n");
        WriteState(new
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
            PendingTrimSlot = -1,
            PendingTrimBytes = (long)original.Length - Budget,
            PendingTrimLength = (long)original.Length,
            PendingTrimVolume = volume,
            PendingTrimFileIndex = index,
            PendingTrimTailSha256 = Convert.ToHexString(SHA256.HashData(original.AsSpan(original.Length - Budget))),
            PendingTrimPublishedSha256 = Convert.ToHexString(SHA256.HashData(replacement)),
        });
        var actualReplacement = replacement.ToArray();
        if (unexpected)
        {
            var target = Encoding.UTF8.GetString(actualReplacement).IndexOf("target", StringComparison.Ordinal);
            Assert.True(target >= 0);
            actualReplacement[target] = (byte)'x';
        }
        File.WriteAllBytes(PathName + ".replacement", actualReplacement);
        File.Move(PathName + ".replacement", PathName, overwrite: true);
        if (proofMissing)
        {
            File.Delete(PathName + ".corrupt.jsonl");
        }
        if (mainMissing)
        {
            File.Delete(PathName);
        }
        var before = Directory.GetFiles(_root).ToDictionary(f => f, File.ReadAllBytes);
        _ = new ActionJournal(PathName).ReadWithCoverage();
        Assert.All(before, pair => Assert.Equal(pair.Value, File.ReadAllBytes(pair.Key)));
        var journal = new ActionJournal(PathName);
        Assert.True(journal.TryAppend(Entry()));
        Assert.Equal(unexpected || mainMissing ? 0 : original.Length - Budget,
            SnapshotLong(journal.ReadWithCoverage(), "DiscardedJournalPrefixBytes"));
        Assert.Equal(unexpected || proofMissing || mainMissing, journal.ReadWithCoverage().EvidenceCountersUnknown);
        if (unexpected || mainMissing)
        {
            Assert.Equal(original.Length - Budget, SnapshotLong(journal.ReadWithCoverage(), "UnverifiedPrefixDiscardBytes"));
        }
        Assert.True(journal.TryAppend(Entry()));
        Assert.Equal(unexpected || mainMissing ? 0 : original.Length - Budget,
            SnapshotLong(journal.ReadWithCoverage(), "DiscardedJournalPrefixBytes"));
    }

    [Fact]
    public async Task ConcurrentWritersMigrateALegacyJournalWithoutDoubleCounting()
    {
        const string variable = "WINSIGHT_TEST_LEGACY_WRITER_PATH";
        if (Environment.GetEnvironmentVariable(variable) is { } childPath)
        {
            var child = new ActionJournal(childPath);
            for (var i = 0; i < 24; i++)
            {
                Assert.True(child.TryAppend(Entry("child-writer")));
            }
            return;
        }
        _ = CreateLegacyHistory();
        var expectedPrefixLoss = new FileInfo(PathName).Length - Budget;
        var children = new List<Process>();
        try
        {
            for (var i = 0; i < 2; i++)
            {
                var start = new ProcessStartInfo("dotnet")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                start.ArgumentList.Add("vstest");
                start.ArgumentList.Add(typeof(LegacyActionJournalRecoveryTests).Assembly.Location);
                start.ArgumentList.Add("/TestCaseFilter:FullyQualifiedName=WinSight.Application.Tests.LegacyActionJournalRecoveryTests.ConcurrentWritersMigrateALegacyJournalWithoutDoubleCounting");
                start.Environment[variable] = PathName;
                children.Add(Process.Start(start)!);
            }
            await Task.WhenAll(children.Select(async child =>
            {
                var stdout = child.StandardOutput.ReadToEndAsync();
                var stderr = child.StandardError.ReadToEndAsync();
                await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));
                Assert.True(child.ExitCode == 0, await stdout + await stderr);
            }));
            var journal = new ActionJournal(PathName);
            Assert.Equal(48, journal.Read(0).Count(row => row.Target == "child-writer"));
            Assert.Equal(expectedPrefixLoss, SnapshotLong(journal.ReadWithCoverage(), "DiscardedJournalPrefixBytes"));
        }
        finally
        {
            foreach (var child in children)
            {
                if (!child.HasExited)
                {
                    child.Kill(entireProcessTree: true);
                    await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
                }
                child.Dispose();
            }
        }
    }

    private ActionJournalEntry CreateLegacyHistory()
    {
        ActionJournalEntry? newest = null;
        using var writer = new StreamWriter(PathName, false, new UTF8Encoding(false));
        for (var i = 0; i < 10_000; i++)
        {
            newest = Entry(new string('t', 1700));
            writer.WriteLine(JsonSerializer.Serialize(newest));
        }
        return newest!;
    }
    private void WriteState(object state) => File.WriteAllText(PathName + ".evidence.json", JsonSerializer.Serialize(state));
    private static long SnapshotLong(ActionJournalSnapshot snapshot, string property)
    {
        var member = typeof(ActionJournalSnapshot).GetProperty(property);
        Assert.NotNull(member);
        return Convert.ToInt64(member.GetValue(snapshot), System.Globalization.CultureInfo.InvariantCulture);
    }
}
