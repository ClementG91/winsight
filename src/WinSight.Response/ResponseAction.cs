namespace WinSight.Response;

/// <summary>The kind of operator-confirmed response WinSight can carry out.</summary>
public enum ResponseActionKind
{
    /// <summary>Suspend every thread of a process so it stops making progress; reversible.</summary>
    SuspendProcess,

    /// <summary>Resume a process previously suspended by WinSight.</summary>
    ResumeProcess,

    /// <summary>Terminate a process. Not reversible; the strongest process action.</summary>
    TerminateProcess,

    /// <summary>Move a persistence entry to quarantine and remove it from the live surface.</summary>
    QuarantinePersistence,

    /// <summary>Restore a quarantined persistence entry to where it came from.</summary>
    RestorePersistence,

    /// <summary>Disable a persistence entry in place (a service or task) without removing it.</summary>
    DisablePersistence,

    /// <summary>Add an allow/ignore or block rule.</summary>
    AddRule,

    /// <summary>Remove a previously added rule.</summary>
    RemoveRule,
}

/// <summary>Whether a response action succeeded, and if not, exactly why.</summary>
public enum ResponseOutcome
{
    Succeeded,

    /// <summary>The target changed since the alert (pid reused, image replaced, value edited).</summary>
    TargetChanged,

    /// <summary>The target no longer exists (process gone, value already removed).</summary>
    TargetNotFound,

    /// <summary>The target is a protected/critical process or a WinSight process.</summary>
    TargetProtected,

    /// <summary>The action needs the privileged service and it was not available or not authorised.</summary>
    NotAuthorized,

    /// <summary>The action is not supported for this target on this machine.</summary>
    NotSupported,

    /// <summary>A recoverable failure while carrying the action out (I/O, access, transient OS error).</summary>
    Failed,

    /// <summary>The operator has an allow rule that covers this target; the action was skipped.</summary>
    SuppressedByRule,
}

/// <summary>The privilege an action requires.</summary>
public enum ResponsePrivilege
{
    /// <summary>Runs in the unprivileged dashboard against the current user's own objects.</summary>
    CurrentUser,

    /// <summary>Runs in the LocalSystem service under its administrator-only capability tier.</summary>
    Service,
}

/// <summary>The outcome of one response action, kept whole so it can be journalled and shown.</summary>
/// <param name="ActionId">A unique id correlating the request, its journal entry and any undo.</param>
/// <param name="Kind">The action attempted.</param>
/// <param name="Outcome">Whether it succeeded and, if not, the stable reason.</param>
/// <param name="Target">A short, non-sensitive description of what was acted on (name, not payload).</param>
/// <param name="AtUtc">When the attempt completed.</param>
/// <param name="Reversible">Whether an undo action exists for this result.</param>
/// <param name="Detail">An optional short, non-sensitive clarification. Never a stack trace.</param>
public sealed record ResponseResult(
    Guid ActionId,
    ResponseActionKind Kind,
    ResponseOutcome Outcome,
    string Target,
    DateTimeOffset AtUtc,
    bool Reversible,
    string? Detail = null)
{
    public bool Succeeded => Outcome == ResponseOutcome.Succeeded;
}
