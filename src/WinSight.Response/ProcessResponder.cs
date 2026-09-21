namespace WinSight.Response;

/// <summary>The controller-level result before it is mapped to the public response outcome.</summary>
public enum ProcessControlOutcome
{
    Succeeded,
    TargetChanged,
    Failed,

    /// <summary>
    /// Suspension failed and at least one thread that had already been suspended could not be
    /// proven resumed. The operator must be told that the process may be partially suspended.
    /// </summary>
    RollbackIncomplete,
}

/// <summary>Carries out a process action once the decision to act has been made.</summary>
public interface IProcessController
{
    /// <summary>
    /// Suspends every thread of the process <paramref name="expected"/> describes. False on any
    /// recoverable failure, including a process that is no longer the one expected. A failed rollback
    /// is reported explicitly rather than hidden behind a generic false result.
    /// </summary>
    ProcessControlOutcome SuspendThreads(ProcessIdentity expected);

    /// <summary>Resumes every thread of the expected process.</summary>
    ProcessControlOutcome ResumeThreads(ProcessIdentity expected);

    /// <summary>Terminates the expected process.</summary>
    ProcessControlOutcome TerminateProcess(ProcessIdentity expected);
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
    private readonly IActionJournal _journal;
    private readonly Func<DateTimeOffset> _clock;

    public ProcessResponder(
        IProcessInspector inspector,
        IProcessController controller,
        IActionJournal? journal = null,
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
        ResponseActionKind kind, ProcessIdentity captured, string target, bool reversible,
        Func<ProcessIdentity, ProcessControlOutcome> operation)
    {
        ArgumentNullException.ThrowIfNull(captured);
        var actionId = Guid.NewGuid();
        var preparedAt = _clock();
        if (!_journal.TryAppend(new ActionJournalEntry(
                actionId, kind, ResponseOutcome.AuditPrepared, target, preparedAt,
                Reversible: false, Phase: ActionJournalPhase.Prepared)))
        {
            return new ResponseResult(actionId, kind, ResponseOutcome.Failed, target, preparedAt,
                Reversible: false,
                Detail: "action was not attempted because its audit intent could not be written");
        }
        var outcome = Evaluate(captured, operation);
        var result = new ResponseResult(actionId, kind, outcome, target, _clock(),
            Reversible: reversible && outcome == ResponseOutcome.Succeeded,
            Detail: outcome == ResponseOutcome.PartiallyApplied
                ? "suspension rollback was incomplete; one or more threads may still be suspended"
                : null);
        if (_journal.TryAppend(new ActionJournalEntry(
                actionId, kind, outcome, target, result.AtUtc, result.Reversible)))
        {
            return result;
        }
        var applied = outcome is ResponseOutcome.Succeeded or ResponseOutcome.PartiallyApplied;
        return result with
        {
            Outcome = applied ? ResponseOutcome.PartiallyApplied : outcome,
            Detail = AppendDetail(result.Detail,
                applied
                    ? "the action may have changed the target, but its completion could not be journalled"
                    : "the refusal/failure completion could not be journalled"),
        };
    }

    private static string AppendDetail(string? existing, string addition) =>
        string.IsNullOrEmpty(existing) ? addition : $"{existing}; {addition}";

    private ResponseOutcome Evaluate(
        ProcessIdentity captured, Func<ProcessIdentity, ProcessControlOutcome> operation)
    {
        if (ProtectedProcesses.IsAlwaysProtected(captured.Pid))
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
        if (ProtectedProcesses.IsProtected(current))
        {
            return ResponseOutcome.TargetProtected;
        }
        // The controller re-checks the start time on the one handle it acts through, so a process
        // that exits and hands its pid on after this line is refused there rather than acted on.
        return operation(captured) switch
        {
            ProcessControlOutcome.Succeeded => ResponseOutcome.Succeeded,
            ProcessControlOutcome.TargetChanged => ResponseOutcome.TargetChanged,
            ProcessControlOutcome.RollbackIncomplete => ResponseOutcome.PartiallyApplied,
            _ => ResponseOutcome.Failed,
        };
    }
}
