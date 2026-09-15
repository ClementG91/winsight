namespace WinSight.Response;

/// <summary>Carries out a process action once the decision to act has been made.</summary>
public interface IProcessController
{
    /// <summary>Suspends every thread of the process. False on any recoverable failure.</summary>
    bool SuspendThreads(int pid);

    /// <summary>Resumes every thread of the process. False on any recoverable failure.</summary>
    bool ResumeThreads(int pid);

    /// <summary>Terminates the process. False on any recoverable failure.</summary>
    bool TerminateProcess(int pid);
}

/// <summary>
/// The safe path from "the operator chose to act on this process" to the action actually happening:
/// revalidate the captured identity against the live process, refuse protected processes, perform the
/// action, and record the result.
/// </summary>
/// <remarks>
/// Every guard here exists because skipping it acts on the wrong thing: a reused pid, a replaced
/// image, or a core Windows process whose death takes the machine down. Suspension is reversible and
/// is the default response; termination is offered but never automatic.
/// </remarks>
public sealed class ProcessResponder
{
    private readonly IProcessInspector _inspector;
    private readonly IProcessController _controller;
    private readonly ActionJournal _journal;
    private readonly Func<DateTimeOffset> _clock;

    public ProcessResponder(
        IProcessInspector inspector,
        IProcessController controller,
        ActionJournal? journal = null,
        Func<DateTimeOffset>? clock = null)
    {
        _inspector = inspector ?? throw new ArgumentNullException(nameof(inspector));
        _controller = controller ?? throw new ArgumentNullException(nameof(controller));
        _journal = journal ?? new ActionJournal();
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>Suspends the process, if it is still the one captured and not protected.</summary>
    public ResponseResult Suspend(ProcessIdentity captured, string target) =>
        Act(ResponseActionKind.SuspendProcess, captured, target, reversible: true, _controller.SuspendThreads);

    /// <summary>Resumes a process WinSight suspended.</summary>
    public ResponseResult Resume(ProcessIdentity captured, string target) =>
        Act(ResponseActionKind.ResumeProcess, captured, target, reversible: false, _controller.ResumeThreads);

    /// <summary>Terminates the process, if it is still the one captured and not protected.</summary>
    public ResponseResult Terminate(ProcessIdentity captured, string target) =>
        Act(ResponseActionKind.TerminateProcess, captured, target, reversible: false, _controller.TerminateProcess);

    private ResponseResult Act(
        ResponseActionKind kind, ProcessIdentity captured, string target, bool reversible, Func<int, bool> operation)
    {
        ArgumentNullException.ThrowIfNull(captured);
        var actionId = Guid.NewGuid();
        var outcome = Evaluate(captured, operation);
        var result = new ResponseResult(actionId, kind, outcome, target, _clock(),
            Reversible: reversible && outcome == ResponseOutcome.Succeeded);
        _journal.TryAppend(new ActionJournalEntry(
            actionId, kind, outcome, target, result.AtUtc, result.Reversible));
        return result;
    }

    private ResponseOutcome Evaluate(ProcessIdentity captured, Func<int, bool> operation)
    {
        var imageFileName = _inspector.ImageFileName(captured.Pid);
        if (ProtectedProcesses.IsProtected(captured.Pid, imageFileName))
        {
            return ResponseOutcome.TargetProtected;
        }
        var current = _inspector.Capture(captured.Pid, hashImage: captured.ImageSha256 is not null);
        if (current is null)
        {
            return ResponseOutcome.TargetNotFound;
        }
        if (!captured.Matches(current))
        {
            return ResponseOutcome.TargetChanged;
        }
        return operation(captured.Pid) ? ResponseOutcome.Succeeded : ResponseOutcome.Failed;
    }
}
