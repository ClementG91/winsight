namespace WinSight.Response;

/// <summary>
/// Observed response diagnostics for presentation, without parsing technical prose or repeating IO.
/// Reasons are independent: a reassertion or incomplete rollback can coexist with an audit gap.
/// This informational value neither authorizes an action nor substitutes for durable journal evidence.
/// </summary>
public sealed record ResponseDiagnostics
{
    public ActionJournalWriteResult? AuditIntent { get; init; }
    public ActionJournalWriteResult? AuditCompletion { get; init; }
    public RuleStoreResult? RuleMutation { get; init; }
    public AllowRollbackDiagnostic? AllowRollback { get; init; }
    public bool PersistenceReasserted { get; init; }
    public bool ProcessRollbackIncomplete { get; init; }
}

/// <summary>The state actually established by an Allow rollback; the default never claims absence.</summary>
public enum AllowRollbackState
{
    Unconfirmed,
    ConfirmedAbsent,
    ConfirmedActive,
    TargetChanged,
}

/// <summary>Retains the original rollback outcome and storage result without guessing activity.</summary>
public sealed record AllowRollbackDiagnostic(
    ResponseOutcome Outcome,
    RuleStoreResult Storage,
    AllowRollbackState State);
