using Xunit;

namespace WinSight.Response.Tests;

public sealed class ProcessResponderTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 14, 12, 0, 0, TimeSpan.Zero);

    private static ProcessIdentity Identity(int pid = 4321, long start = 100, string path = @"C:\app\evil.exe", string? hash = null) =>
        new(pid, start, path, hash);

    private static ProcessResponder Responder(FakeInspector inspector, FakeController controller, string journal) =>
        new(inspector, controller, new ActionJournal(journal), () => T0);

    [Fact]
    public void SuspendActsWhenTheProcessIsStillTheOneCaptured()
    {
        var captured = Identity();
        var inspector = new FakeInspector { Current = captured, FileName = "evil.exe" };
        var controller = new FakeController();
        using var journal = new TempFile();

        var result = Responder(inspector, controller, journal.Path).Suspend(captured, "evil.exe");

        Assert.Equal(ResponseOutcome.Succeeded, result.Outcome);
        Assert.True(result.Reversible);
        Assert.Equal([captured.Pid], controller.Suspended);
        var entry = Assert.Single(new ActionJournal(journal.Path).Read());
        Assert.Equal(result.ActionId, entry.ActionId);
        Assert.Equal(ResponseActionKind.SuspendProcess, entry.Kind);
    }

    [Fact]
    public void AReusedPidWithADifferentStartTimeIsRefusedAsChanged()
    {
        var captured = Identity(start: 100);
        var inspector = new FakeInspector { Current = captured with { StartTimestampUtcTicks = 999 }, FileName = "other.exe" };
        var controller = new FakeController();
        using var journal = new TempFile();

        var result = Responder(inspector, controller, journal.Path).Terminate(captured, "evil.exe");

        Assert.Equal(ResponseOutcome.TargetChanged, result.Outcome);
        Assert.Empty(controller.Terminated);
    }

    [Fact]
    public void AReplacedImageHashIsRefusedAsChanged()
    {
        var captured = Identity(hash: "AAAA");
        var inspector = new FakeInspector { Current = captured with { ImageSha256 = "BBBB" }, FileName = "evil.exe" };
        var controller = new FakeController();
        using var journal = new TempFile();

        var result = Responder(inspector, controller, journal.Path).Suspend(captured, "evil.exe");

        Assert.Equal(ResponseOutcome.TargetChanged, result.Outcome);
        Assert.Empty(controller.Suspended);
    }

    [Fact]
    public void AProcessThatExitedIsRefusedAsNotFound()
    {
        var captured = Identity();
        var inspector = new FakeInspector { Current = null, FileName = "evil.exe" };
        var controller = new FakeController();
        using var journal = new TempFile();

        var result = Responder(inspector, controller, journal.Path).Terminate(captured, "evil.exe");

        Assert.Equal(ResponseOutcome.TargetNotFound, result.Outcome);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    public void AReservedProcessIsNeverActedOn(int pid)
    {
        var captured = Identity(pid: pid);
        var inspector = new FakeInspector { Current = captured };
        var controller = new FakeController();
        using var journal = new TempFile();

        var result = Responder(inspector, controller, journal.Path).Terminate(captured, "reserved");

        Assert.Equal(ResponseOutcome.TargetProtected, result.Outcome);
        Assert.Empty(controller.Terminated);
        Assert.Empty(controller.Suspended);
    }

    [Fact]
    public void AWindowsCriticalProcessAtItsVerifiedSystemPathIsNeverActedOn()
    {
        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "lsass.exe");
        var captured = Identity(pid: 9000, path: path);
        var inspector = new FakeInspector { Current = captured };
        var controller = new FakeController();
        using var journal = new TempFile();

        var result = Responder(inspector, controller, journal.Path).Terminate(captured, "lsass.exe");

        Assert.Equal(ResponseOutcome.TargetProtected, result.Outcome);
        Assert.Empty(controller.Terminated);
    }

    [Fact]
    public void AProcessOnlyRenamedLikeAProtectedBinaryDoesNotEvadeResponse()
    {
        var captured = Identity(pid: 9000, path: @"C:\Users\me\AppData\Local\Temp\lsass.exe");
        var inspector = new FakeInspector { Current = captured };
        var controller = new FakeController();
        using var journal = new TempFile();

        var result = Responder(inspector, controller, journal.Path).Terminate(captured, "lsass.exe");

        Assert.Equal(ResponseOutcome.Succeeded, result.Outcome);
        Assert.Equal([captured.Pid], controller.Terminated);
    }

    [Fact]
    public void AControllerFailureIsReportedAsFailedAndJournalled()
    {
        var captured = Identity();
        var inspector = new FakeInspector { Current = captured, FileName = "evil.exe" };
        var controller = new FakeController { Succeed = false };
        using var journal = new TempFile();

        var result = Responder(inspector, controller, journal.Path).Suspend(captured, "evil.exe");

        Assert.Equal(ResponseOutcome.Failed, result.Outcome);
        Assert.False(result.Reversible);
        Assert.Equal(ResponseOutcome.Failed, Assert.Single(new ActionJournal(journal.Path).Read()).Outcome);
    }

    [Fact]
    public void AnIncompleteSuspendRollbackIsNeverReportedAsAnOrdinaryFailure()
    {
        var captured = Identity();
        var inspector = new FakeInspector { Current = captured, FileName = "evil.exe" };
        var controller = new FakeController { Outcome = ProcessControlOutcome.RollbackIncomplete };
        using var journal = new TempFile();

        var result = Responder(inspector, controller, journal.Path).Suspend(captured, "evil.exe");

        Assert.Equal(ResponseOutcome.PartiallyApplied, result.Outcome);
        Assert.False(result.Reversible);
        Assert.Contains("may still be suspended", result.Detail, StringComparison.Ordinal);
        Assert.Equal(ResponseOutcome.PartiallyApplied,
            Assert.Single(new ActionJournal(journal.Path).Read()).Outcome);
    }

    [Fact]
    public void ResumeUndoesASuspensionAndIsRecordedSeparately()
    {
        var captured = Identity();
        var inspector = new FakeInspector { Current = captured, FileName = "evil.exe" };
        var controller = new FakeController();
        using var journal = new TempFile();
        var responder = Responder(inspector, controller, journal.Path);

        responder.Suspend(captured, "evil.exe");
        var resume = responder.Resume(captured, "evil.exe");

        Assert.Equal(ResponseOutcome.Succeeded, resume.Outcome);
        Assert.Equal([captured.Pid], controller.Resumed);
        Assert.Equal(2, new ActionJournal(journal.Path).Read().Count);
    }

    [Fact]
    public void AnUnavailableAuditIntentPreventsTheProcessAction()
    {
        var captured = Identity();
        var inspector = new FakeInspector { Current = captured, FileName = "evil.exe" };
        var controller = new FakeController();
        var journal = new SequencedJournal(false);
        var responder = new ProcessResponder(inspector, controller, journal, () => T0);

        var result = responder.Terminate(captured, "evil.exe");

        Assert.Equal(ResponseOutcome.Failed, result.Outcome);
        Assert.Contains("not attempted", result.Detail, StringComparison.Ordinal);
        Assert.Empty(controller.Terminated);
    }

    [Fact]
    public void ACompletionJournalFailureCannotReadAsAFullSuccess()
    {
        var captured = Identity();
        var inspector = new FakeInspector { Current = captured, FileName = "evil.exe" };
        var controller = new FakeController();
        var journal = new SequencedJournal(true, false);
        var responder = new ProcessResponder(inspector, controller, journal, () => T0);

        var result = responder.Terminate(captured, "evil.exe");

        Assert.Equal(ResponseOutcome.PartiallyApplied, result.Outcome);
        Assert.Contains("could not be journalled", result.Detail, StringComparison.Ordinal);
        Assert.Equal([captured.Pid], controller.Terminated);
        Assert.Equal(ActionJournalPhase.Prepared, Assert.Single(journal.Written).Phase);
    }

    private sealed class FakeInspector : IProcessInspector
    {
        public ProcessIdentity? Current { get; set; }
        public string? FileName { get; set; }
        public ProcessIdentity? Capture(int pid, bool hashImage = false) => Current;
    }

    private sealed class FakeController : IProcessController
    {
        public bool Succeed
        {
            get => Outcome == ProcessControlOutcome.Succeeded;
            set => Outcome = value ? ProcessControlOutcome.Succeeded : ProcessControlOutcome.Failed;
        }
        public ProcessControlOutcome Outcome { get; set; } = ProcessControlOutcome.Succeeded;
        public List<int> Suspended { get; } = [];
        public List<int> Resumed { get; } = [];
        public List<int> Terminated { get; } = [];
        public ProcessControlOutcome SuspendThreads(ProcessIdentity expected) { if (Succeed) { Suspended.Add(expected.Pid); } return Outcome; }
        public ProcessControlOutcome ResumeThreads(ProcessIdentity expected) { if (Succeed) { Resumed.Add(expected.Pid); } return Outcome; }
        public ProcessControlOutcome TerminateProcess(ProcessIdentity expected) { if (Succeed) { Terminated.Add(expected.Pid); } return Outcome; }
    }

    private sealed class SequencedJournal(params bool[] outcomes) : IActionJournal
    {
        private readonly Queue<bool> _outcomes = new(outcomes);
        public List<ActionJournalEntry> Written { get; } = [];

        public bool TryAppend(ActionJournalEntry entry)
        {
            var succeeds = _outcomes.Count == 0 || _outcomes.Dequeue();
            if (succeeds)
            {
                Written.Add(entry);
            }
            return succeeds;
        }

        public void MarkUndone(Guid actionId, Guid undoActionId)
        {
        }

        public IReadOnlyList<ActionJournalEntry> Read(int max = 200) => Written;
    }
}

internal sealed class TempFile : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(
        System.IO.Path.GetTempPath(), $"winsight-response-{Guid.NewGuid():N}");

    public void Dispose()
    {
        try
        {
            if (File.Exists(Path))
            {
                File.Delete(Path);
            }
        }
        catch (IOException)
        {
        }
    }
}
