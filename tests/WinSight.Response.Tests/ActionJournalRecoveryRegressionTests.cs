using System.Security.Cryptography;
using System.Diagnostics;
using System.Text;
using System.Text.Json;

using Xunit;

namespace WinSight.Response.Tests;

public sealed class ActionJournalRecoveryRegressionTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-recovery-regression-").FullName;
    private string PathName => Path.Combine(_root, "history.jsonl");
    private static readonly ProcessIdentity Identity = new(4321, 100, @"D:\fixture\evil.exe", null);
    public void Dispose() => Directory.Delete(_root, recursive: true);
    private static ActionJournalEntry Entry(string target = "target") => new(Guid.NewGuid(),
        ResponseActionKind.AddRule, ResponseOutcome.Succeeded, target, DateTimeOffset.UtcNow, true);

    [Fact]
    public void SecondTornWriteDoesNotPreventSuspendResumeOrTerminate()
    {
        const string earlier = "evidence from earlier recovery\n";
        File.WriteAllText(PathName + ".corrupt.jsonl", earlier);
        var original = JsonSerializer.Serialize(Entry()) + "\n{\"ActionId\":\"6f1c";
        File.WriteAllText(PathName, original);
        var controller = new Controller();
        var responder = new ProcessResponder(new Inspector(), controller, new ActionJournal(PathName));
        for (var i = 0; i < 3; i++)
        {
            Assert.Equal(ResponseOutcome.Succeeded, responder.Suspend(Identity, "fixture").Outcome);
            Assert.Equal(ResponseOutcome.Succeeded, responder.Resume(Identity, "fixture").Outcome);
            Assert.Equal(ResponseOutcome.Succeeded, responder.Terminate(Identity, "fixture").Outcome);
        }
        Assert.Equal(9, controller.Calls);
        Assert.StartsWith(original, File.ReadAllText(PathName), StringComparison.Ordinal);
        Assert.Equal(earlier, File.ReadAllText(PathName + ".corrupt.jsonl"));
    }

    [Fact]
    public void RotationRecoversAfterATransientRenameConflict()
    {
        var original = RetentionSource();
        File.WriteAllText(PathName, original);
        var journal = new ActionJournal(PathName);
        using (new FileStream(PathName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            Assert.Equal(ActionJournalWriteStatus.RotationFailed, journal.TryAppendWithStatus(Entry()).Status);
        }
        Assert.True(journal.TryAppend(Entry()));
        AssertEvidenceContains(original);
        var controller = new Controller();
        var responder = new ProcessResponder(new Inspector(), controller, journal);
        Assert.Equal(ResponseOutcome.Succeeded, responder.Resume(Identity, "fixture").Outcome);
        Assert.Equal(1, controller.Calls);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ExistingIdenticalOrDifferentEvidenceDoesNotBlockRetention(bool identical)
    {
        var original = RetentionSource();
        const string previous = "previous distinct corruption\n";
        File.WriteAllText(PathName, original);
        File.WriteAllText(PathName + ".corrupt.jsonl", identical ? original : previous);
        Assert.True(new ActionJournal(PathName).TryAppend(Entry()));
        AssertEvidenceContains(original);
        if (!identical)
        {
            AssertEvidenceContains(previous);
        }
    }

    [Fact]
    public void EveryBytewiseTornTailRemainsPreservedAndWritable()
    {
        var prefix = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(Entry()) + "\n");
        var final = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(Entry("\u0436\U0001F600")) + "\n");
        File.WriteAllText(PathName + ".corrupt.jsonl", "earlier evidence");
        for (var cut = 0; cut < final.Length; cut++)
        {
            var original = prefix.Concat(final.Take(cut)).ToArray();
            File.WriteAllBytes(PathName, original);
            Assert.True(new ActionJournal(PathName).TryAppend(Entry($"cut{cut}")), $"cut at byte {cut}");
            Assert.Equal(original, File.ReadAllBytes(PathName).Take(original.Length));
        }
    }

    [Fact]
    public void StorageRefusalNamesItsTypedStatusAndDoesNotMutate()
    {
        var controller = new Controller();
        var responder = new ProcessResponder(new Inspector(), controller,
            new ActionJournal("D:\\invalid\0history.jsonl"));
        var result = responder.Resume(Identity, "fixture");
        Assert.Equal(ResponseOutcome.Failed, result.Outcome);
        Assert.Contains("Unavailable", result.Detail, StringComparison.Ordinal);
        Assert.Equal(0, controller.Calls);
        Assert.NotNull(typeof(IActionJournal).GetMethod("TryAppendWithStatus"));
    }

    [Fact]
    public void RepeatedRecoveryHasABoundedEvidenceBudgetAndVisibleLossAccounting()
    {
        long originalBytes = 0;
        for (var i = 0; i < 8; i++)
        {
            var original = RetentionSource();
            originalBytes += Encoding.UTF8.GetByteCount(original);
            File.WriteAllText(PathName, original, new UTF8Encoding(false));
            Assert.True(new ActionJournal(PathName).TryAppend(Entry()));
            AssertEvidenceContains(original);
        }
        var files = Directory.GetFiles(_root, "*.corrupt*.jsonl");
        Assert.Equal(4, files.Length);
        Assert.All(files, f => Assert.InRange(new FileInfo(f).Length, 1, 16 * 1024 * 1024));
        var snapshot = new ActionJournal(PathName).ReadWithCoverage();
        var lost = SnapshotLong(snapshot, "DiscardedEvidenceBytes");
        Assert.Equal(originalBytes - files.Sum(f => new FileInfo(f).Length), lost);
        Assert.Equal(4, SnapshotLong(snapshot, "DiscardedEvidenceFiles"));
        Assert.Equal("evidence-budget", typeof(ActionJournalSnapshot).GetProperty("EvidenceLossReason")?.GetValue(snapshot));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PendingEvictionResumesAfterDeletionOrALockedAttempt(bool alreadyDeleted)
    {
        var original = RetentionSource();
        File.WriteAllText(PathName, original);
        for (var i = 0; i < 4; i++)
        {
            File.WriteAllText(EvidencePath(i), $"evidence{i}");
        }
        var old = File.ReadAllBytes(EvidencePath(0));
        var pending = new
        {
            Version = 1,
            DiscardedBytes = 0L,
            DiscardedFiles = 0L,
            LossReason = "",
            PriorCountersUnknown = false,
            NextSlot = 0,
            PendingSlot = 0,
            PendingBytes = (long)old.Length,
            PendingSha256 = Convert.ToHexString(SHA256.HashData(old)),
        };
        File.WriteAllText(PathName + ".evidence.json", JsonSerializer.Serialize(pending));
        if (alreadyDeleted)
        {
            File.Delete(EvidencePath(0));
        }
        else
        {
            using var locked = new FileStream(EvidencePath(0), FileMode.Open, FileAccess.Read, FileShare.Read);
            Assert.False(new ActionJournal(PathName).TryAppend(Entry()));
            Assert.Equal(original, File.ReadAllText(PathName));
        }
        var before = Directory.GetFiles(_root).ToDictionary(f => f, File.ReadAllBytes);
        _ = new ActionJournal(PathName).ReadWithCoverage();
        Assert.All(before, pair => Assert.Equal(pair.Value, File.ReadAllBytes(pair.Key)));
        Assert.True(new ActionJournal(PathName).TryAppend(Entry()));
        AssertEvidenceContains(original);
        Assert.Equal(old.Length, SnapshotLong(new ActionJournal(PathName).ReadWithCoverage(), "DiscardedEvidenceBytes"));
    }

    [Fact]
    public void UndoPreservesTheDamagedSourceBeforeRewriting()
    {
        var row = Entry();
        var original = JsonSerializer.Serialize(row) + "\n{ torn undo tail";
        File.WriteAllText(PathName, original);
        File.WriteAllText(EvidencePath(0), "older proof");
        var journal = new ActionJournal(PathName);
        Assert.True(journal.TryMarkUndone(row.ActionId, Guid.NewGuid()).Durable);
        AssertEvidenceContains(original);
        AssertEvidenceContains("older proof");
    }

    [Fact]
    public void MutexIsSharedAcrossWindowsSessionsForTheSamePath()
    {
        Assert.StartsWith(@"Global\", ActionJournal.LockNameFor(PathName), StringComparison.Ordinal);
    }

    [Fact]
    public void CorruptMetadataRecoversWithoutPretendingItsOldCountersAreKnown()
    {
        File.WriteAllText(PathName + ".evidence.json", "{ interrupted metadata");
        for (var i = 0; i < 2; i++)
        {
            File.WriteAllText(PathName, RetentionSource());
            Assert.True(new ActionJournal(PathName).TryAppend(Entry()));
            var snapshot = new ActionJournal(PathName).ReadWithCoverage();
            Assert.Equal(true, typeof(ActionJournalSnapshot).GetProperty("EvidenceCountersUnknown")?.GetValue(snapshot));
            Assert.Equal(22, SnapshotLong(snapshot, "DiscardedMetadataBytes"));
        }
    }

    [Fact]
    public void APartialCopyLeftByACrashIsReplacedBeforeItCanBecomeEvidence()
    {
        var original = RetentionSource();
        File.WriteAllText(PathName, original);
        File.WriteAllText(EvidencePath(0) + ".winsight-journal.tmp", "partial copy");
        File.WriteAllText(PathName + ".winsight-journal.tmp", "partial rotation");
        Assert.True(new ActionJournal(PathName).TryAppend(Entry()));
        AssertEvidenceContains(original);
        Assert.Empty(Directory.GetFiles(_root, "*.winsight-journal.tmp"));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"Version\":1}")]
    [InlineData("{\"Version\":99}")]
    public void MissingOrUnknownMetadataNeverSilentlyResetsLossAccounting(string metadata)
    {
        File.WriteAllText(PathName + ".evidence.json", metadata);
        var snapshot = new ActionJournal(PathName).ReadWithCoverage();
        Assert.Equal(true, typeof(ActionJournalSnapshot).GetProperty("EvidenceCountersUnknown")?.GetValue(snapshot));
        Assert.Equal(metadata, File.ReadAllText(PathName + ".evidence.json"));
        File.WriteAllText(PathName, RetentionSource());
        Assert.True(new ActionJournal(PathName).TryAppend(Entry()));
        Assert.Equal(true, typeof(ActionJournalSnapshot).GetProperty("EvidenceCountersUnknown")?.GetValue(new ActionJournal(PathName).ReadWithCoverage()));
    }

    [Fact]
    public async Task TwoSeparateWriterProcessesPreserveEveryDurableRecord()
    {
        const string pathVariable = "WINSIGHT_TEST_JOURNAL_WRITER_PATH";
        if (Environment.GetEnvironmentVariable(pathVariable) is { } childPath)
        {
            var child = new ActionJournal(childPath);
            for (var i = 0; i < 24; i++)
            {
                Assert.True(child.TryAppend(Entry()));
            }
            return;
        }
        var children = Enumerable.Range(0, 2).Select(_ =>
        {
            var start = new ProcessStartInfo("dotnet")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            start.ArgumentList.Add("vstest");
            start.ArgumentList.Add(typeof(ActionJournalRecoveryRegressionTests).Assembly.Location);
            start.ArgumentList.Add("/TestCaseFilter:FullyQualifiedName=WinSight.Response.Tests.ActionJournalRecoveryRegressionTests.TwoSeparateWriterProcessesPreserveEveryDurableRecord");
            start.Environment[pathVariable] = PathName;
            return Process.Start(start)!;
        }).ToArray();
        try
        {
            var outputs = children.Select(async child =>
            {
                var stdout = child.StandardOutput.ReadToEndAsync();
                var stderr = child.StandardError.ReadToEndAsync();
                await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));
                var diagnostic = await stdout + await stderr;
                Assert.True(child.ExitCode == 0, diagnostic);
            });
            await Task.WhenAll(outputs);
            var rows = new ActionJournal(PathName).Read(0);
            Assert.Equal(48, rows.Count);
            Assert.Equal(48, rows.Select(row => row.ActionId).Distinct().Count());
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

    private string EvidencePath(int slot) => slot == 0 ? PathName + ".corrupt.jsonl" : PathName + $".corrupt.{slot}.jsonl";
    private static long SnapshotLong(ActionJournalSnapshot snapshot, string property)
    {
        var member = typeof(ActionJournalSnapshot).GetProperty(property);
        Assert.NotNull(member);
        return Convert.ToInt64(member.GetValue(snapshot), System.Globalization.CultureInfo.InvariantCulture);
    }
    private static string RetentionSource() => "{ corrupted record\n" + string.Concat(
        Enumerable.Range(0, 10_000).Select(_ => JsonSerializer.Serialize(Entry()) + "\n"));
    private void AssertEvidenceContains(string expected) => Assert.Contains(
        Directory.GetFiles(_root, "*.corrupt*.jsonl"), path => File.ReadAllText(path) == expected);
    private sealed class Inspector : IProcessInspector
    {
        public ProcessIdentity? Capture(int pid, bool hashImage = false) => Identity;
    }
    private sealed class Controller : IProcessController
    {
        public int Calls { get; private set; }
        public ProcessControlOutcome SuspendThreads(ProcessIdentity expected) { Calls++; return ProcessControlOutcome.Succeeded; }
        public ProcessControlOutcome ResumeThreads(ProcessIdentity expected) { Calls++; return ProcessControlOutcome.Succeeded; }
        public ProcessControlOutcome TerminateProcess(ProcessIdentity expected) { Calls++; return ProcessControlOutcome.Succeeded; }
    }
}
