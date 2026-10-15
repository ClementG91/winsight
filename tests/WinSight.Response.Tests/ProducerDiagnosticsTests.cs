using Xunit;

namespace WinSight.Response.Tests;

public sealed class ProducerDiagnosticsTests
{
    [Theory]
    [InlineData(ProcessControlOutcome.Succeeded, ActionJournalWriteStatus.Appended)]
    [InlineData(ProcessControlOutcome.Succeeded, ActionJournalWriteStatus.EvidenceRecoveryBlocked)]
    [InlineData(ProcessControlOutcome.RollbackIncomplete, ActionJournalWriteStatus.Appended)]
    [InlineData(ProcessControlOutcome.RollbackIncomplete, ActionJournalWriteStatus.RetentionLimit)]
    [InlineData(ProcessControlOutcome.TargetChanged, ActionJournalWriteStatus.Unavailable)]
    [InlineData(ProcessControlOutcome.Failed, ActionJournalWriteStatus.RotationFailed)]
    public void ProcessReasonsAndActualAuditEvidenceRemainIndependent(ProcessControlOutcome operation, ActionJournalWriteStatus completion)
    {
        var identity = new ProcessIdentity(4321, 100, @"D:\fixture.exe", null);
        var controller = new Controller(operation);
        var journal = new Journal(ActionJournalWriteStatus.Rotated, completion);
        var result = new ProcessResponder(new Inspector(identity), controller, journal).Suspend(identity, "fixture");
        var diagnostics = Assert.IsType<ResponseDiagnostics>(result.Diagnostics);
        Assert.Same(journal.Results[0], diagnostics.AuditIntent);
        Assert.Same(journal.Results[1], diagnostics.AuditCompletion);
        Assert.Equal(operation == ProcessControlOutcome.RollbackIncomplete, diagnostics.ProcessRollbackIncomplete);
        Assert.False(diagnostics.PersistenceReasserted);
        Assert.Null(diagnostics.RuleMutation);
        Assert.Null(diagnostics.AllowRollback);
        Assert.Equal(1, controller.Calls);
        var expected = operation switch
        {
            ProcessControlOutcome.Succeeded => completion == ActionJournalWriteStatus.Appended ? ResponseOutcome.Succeeded : ResponseOutcome.PartiallyApplied,
            ProcessControlOutcome.RollbackIncomplete => ResponseOutcome.PartiallyApplied,
            ProcessControlOutcome.TargetChanged => ResponseOutcome.TargetChanged,
            _ => ResponseOutcome.Failed,
        };
        Assert.Equal(expected, result.Outcome);
        Assert.Equal(operation == ProcessControlOutcome.Succeeded, result.Reversible);
        if (operation == ProcessControlOutcome.RollbackIncomplete) { Assert.Contains("suspension rollback was incomplete", result.Detail, StringComparison.Ordinal); }
        if (completion != ActionJournalWriteStatus.Appended) { Assert.Contains(journal.Results[1].Detail, result.Detail, StringComparison.Ordinal); }
        Assert.Equal(2, journal.Entries.Count);
    }

    [Fact]
    public void ProcessIntentRefusalNeverInvokesTheControllerOrInventsCompletion()
    {
        var identity = new ProcessIdentity(4321, 100, @"D:\fixture.exe", null);
        var controller = new Controller(ProcessControlOutcome.Succeeded);
        var journal = new Journal(ActionJournalWriteStatus.PathTooLong);
        var result = new ProcessResponder(new Inspector(identity), controller, journal).Terminate(identity, "fixture");
        var diagnostics = Assert.IsType<ResponseDiagnostics>(result.Diagnostics);
        Assert.Same(Assert.Single(journal.Results), diagnostics.AuditIntent);
        Assert.Null(diagnostics.AuditCompletion);
        Assert.False(diagnostics.ProcessRollbackIncomplete);
        Assert.Equal(0, controller.Calls);
        Assert.Equal(ResponseOutcome.Failed, result.Outcome);
        Assert.False(result.Reversible);
    }

    [Fact]
    public void ProtectedPidRefusalDoesNotPretendAControllerRollbackOccurred()
    {
        var identity = new ProcessIdentity(4, 100, @"D:\fixture.exe", null);
        var controller = new Controller(ProcessControlOutcome.RollbackIncomplete);
        var journal = new Journal(ActionJournalWriteStatus.Appended, ActionJournalWriteStatus.Unavailable);
        var result = new ProcessResponder(new Inspector(identity), controller, journal).Suspend(identity, "fixture");
        var diagnostics = Assert.IsType<ResponseDiagnostics>(result.Diagnostics);
        Assert.False(diagnostics.ProcessRollbackIncomplete);
        Assert.Equal(ResponseOutcome.TargetProtected, result.Outcome);
        Assert.Equal(0, controller.Calls);
        Assert.Same(journal.Results[1], diagnostics.AuditCompletion);
    }

    private sealed class Inspector(ProcessIdentity identity) : IProcessInspector
    {
        public ProcessIdentity Capture(int pid, bool hashImage = false) => identity;
    }
    private sealed class Controller(ProcessControlOutcome outcome) : IProcessController
    {
        public int Calls { get; private set; }
        public ProcessControlOutcome SuspendThreads(ProcessIdentity expected) { Calls++; return outcome; }
        public ProcessControlOutcome ResumeThreads(ProcessIdentity expected) { Calls++; return outcome; }
        public ProcessControlOutcome TerminateProcess(ProcessIdentity expected) { Calls++; return outcome; }
    }
    private sealed class Journal(params ActionJournalWriteStatus[] statuses) : IActionJournal
    {
        public List<ActionJournalEntry> Entries { get; } = [];
        public List<ActionJournalWriteResult> Results { get; } = [];
        public ActionJournalWriteResult TryAppendWithStatus(ActionJournalEntry entry)
        {
            var result = new ActionJournalWriteResult(statuses[Entries.Count]);
            Entries.Add(entry); Results.Add(result); return result;
        }
        public bool TryAppend(ActionJournalEntry entry) => TryAppendWithStatus(entry).Durable;
        public void MarkUndone(Guid actionId, Guid undoActionId) => throw new InvalidOperationException("No annotation expected");
        public IReadOnlyList<ActionJournalEntry> Read(int max = 200) => Entries;
    }
}
