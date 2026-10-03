using System.Diagnostics;
using System.Text.Json;

using Xunit;

namespace WinSight.Response.Tests;

public sealed class ActionJournalRetentionSupplementTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-action-retention-").FullName;
    private string PathName => Path.Combine(_root, "history.jsonl");
    public void Dispose() => Directory.Delete(_root, recursive: true);
    private static ActionJournalEntry Entry() => new(Guid.NewGuid(), ResponseActionKind.AddRule,
        ResponseOutcome.Succeeded, "target", DateTimeOffset.UtcNow, true);

    [Fact]
    public void RotationAtThePhysicalLimitRetainsTheNewestActionsWithinBothBudgets()
    {
        var rows = Enumerable.Range(0, 10_000).Select(_ => Entry()).ToArray();
        File.WriteAllText(PathName, string.Join("\n", rows.Select(e => JsonSerializer.Serialize(e))) + "\n");
        var newest = Entry();
        var result = new ActionJournal(PathName).TryAppendWithStatus(newest);
        Assert.Equal(ActionJournalWriteStatus.Rotated, result.Status);
        Assert.True(result.Durable);
        var read = new ActionJournal(PathName).ReadWithCoverage(0);
        Assert.Equal(5000, read.Entries.Count);
        Assert.Equal(newest, read.Entries[0]);
        Assert.Equal(rows[^4999], read.Entries[^1]);
        Assert.InRange(new FileInfo(PathName).Length, 1, 8 * 1024 * 1024);
        Assert.False(read.LimitReached);
    }

    [Fact]
    public void LockedRotationReturnsNondurableFailureWithoutLosingTheOldFile()
    {
        var original = string.Concat(Enumerable.Repeat(JsonSerializer.Serialize(Entry()) + "\n", 10_000));
        File.WriteAllText(PathName, original);
        using (var locked = new FileStream(PathName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            var result = new ActionJournal(PathName).TryAppendWithStatus(Entry());
            Assert.Equal(ActionJournalWriteStatus.RotationFailed, result.Status);
            Assert.False(result.Durable);
        }
        Assert.Equal(original, File.ReadAllText(PathName));
    }

    [Fact]
    public void AValidUnterminatedRecordAndATornRecordDoNotMergeWithTheNextAppend()
    {
        var first = Entry();
        File.WriteAllText(PathName, JsonSerializer.Serialize(first));
        var journal = new ActionJournal(PathName);
        Assert.True(journal.TryAppend(Entry()));
        Assert.Equal(2, journal.Read().Count);
        File.AppendAllText(PathName, "{ torn record");
        var original = File.ReadAllBytes(PathName);
        Assert.True(journal.TryAppend(Entry()));
        Assert.Equal(3, journal.Read().Count);
        Assert.Equal(original, File.ReadAllBytes(journal.RecoveryEvidencePath));
        Assert.True(journal.ReadWithCoverage().EvidencePreserved);
    }

    [Fact]
    public async Task IndependentInstancesSerializeConcurrentAppends()
    {
        var rows = Enumerable.Range(0, 32).Select(_ => Entry()).ToArray();
        await Task.WhenAll(rows.Select(e => Task.Run(() => Assert.True(new ActionJournal(PathName).TryAppend(e)))));
        Assert.Equal(rows.Select(e => e.ActionId).Order(),
            new ActionJournal(PathName).Read(0).Select(e => e.ActionId).Order());
    }

    [Fact]
    public void InvalidRecordsAndUnavailableUndoHaveDistinctDiagnostics()
    {
        var journal = new ActionJournal(PathName);
        Assert.Equal(ActionJournalWriteStatus.InvalidRecord,
            journal.TryAppendWithStatus(Entry() with { ActionId = Guid.Empty }).Status);
        Assert.Equal(ActionJournalWriteStatus.InvalidRecord,
            journal.TryMarkUndone(Guid.NewGuid(), Guid.Empty).Status);
        Assert.True(journal.TryAppend(Entry()));
        using var locked = new FileStream(PathName, FileMode.Open, FileAccess.Read, FileShare.None);
        Assert.Equal(ActionJournalWriteStatus.Unavailable,
            journal.TryMarkUndone(Guid.NewGuid(), Guid.NewGuid()).Status);
    }

    [Fact]
    public async Task ASeparateProcessHoldingTheMutexCausesObservableTimeoutAndThenRecovery()
    {
        var start = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-Command");
        start.ArgumentList.Add("$m = [Threading.Mutex]::new($false, $env:WINSIGHT_ACTION_LOCK); "
            + "if (-not $m.WaitOne(5000)) { exit 2 }; try { [Console]::WriteLine('ready'); "
            + "[Console]::ReadLine() | Out-Null } finally { $m.ReleaseMutex(); $m.Dispose() }");
        start.Environment["WINSIGHT_ACTION_LOCK"] = ActionJournal.LockNameFor(PathName);
        using var holder = Process.Start(start)!;
        try
        {
            Assert.Equal("ready", await holder.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(15)));
            var journal = new ActionJournal(PathName, TimeSpan.FromMilliseconds(50));
            Assert.Equal(ActionJournalWriteStatus.Unavailable, journal.TryAppendWithStatus(Entry()).Status);
            Assert.False(File.Exists(PathName));
            await holder.StandardInput.WriteLineAsync("release");
            await holder.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
            Assert.Equal(0, holder.ExitCode);
            Assert.True(journal.TryAppend(Entry()));
        }
        finally
        {
            if (!holder.HasExited)
            {
                holder.Kill(entireProcessTree: true);
                await holder.WaitForExitAsync();
            }
        }
    }
}
