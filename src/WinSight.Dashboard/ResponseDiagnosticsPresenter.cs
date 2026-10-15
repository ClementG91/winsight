using WinSight.Response;

namespace WinSight.Dashboard;

/// <summary>Localized presentation of observed diagnostics, without IO or parsing technical Detail.</summary>
internal static class ResponseDiagnosticsPresenter
{
    private static LocalizationManager Text => LocalizationManager.Instance;

    internal static string ForBlock(ResponseResult result) => Render(result, allow: false, ruleId: null);

    internal static string ForAllow(ResponseResult result, Guid? ruleId) => Render(result, allow: true, ruleId);

    private static string Render(ResponseResult result, bool allow, Guid? ruleId)
    {
        var diagnostics = result.Diagnostics;
        var reassertedBase = !allow && result.Outcome == ResponseOutcome.PartiallyApplied
            && diagnostics?.PersistenceReasserted == true;
        var hasActionId = true;
        string message;
        if (allow && result.Outcome == ResponseOutcome.Succeeded && ruleId is { } storedId)
        {
            message = Text.Format("AlertAllowed", storedId);
        }
        else if (!allow && result.Outcome == ResponseOutcome.Succeeded)
        {
            message = Text.Format("AlertBlocked", result.ActionId);
        }
        else if (reassertedBase)
        {
            message = Text.Format("AlertBlockReasserted", result.ActionId);
        }
        else if (result.Outcome == ResponseOutcome.PartiallyApplied)
        {
            message = Text.Format("AlertPartiallyApplied", result.ActionId);
        }
        else
        {
            message = Text[allow ? "AlertFailed" : AlertWindow.MessageKeyFor(result.Outcome)];
            hasActionId = false;
        }
        var parts = new List<string> { message };
        if (!hasActionId) { parts.Add(Text.Format("ResponseActionId", result.ActionId)); }
        if (diagnostics is null) { return string.Join(' ', parts); }

        if (diagnostics.PersistenceReasserted && !reassertedBase)
        {
            parts.Add(Text.Format("AlertBlockReasserted", result.ActionId));
        }
        if (diagnostics.ProcessRollbackIncomplete)
        {
            parts.Add(Text["ResponseProcessRollbackIncomplete"]);
        }
        if (diagnostics.AuditIntent is { Durable: false } intent)
        {
            parts.Add(Text["ResponseIntentRefused"] + " " + Text[JournalKey(intent.Status)]);
        }
        if (diagnostics.AuditCompletion is { Durable: false } completion)
        {
            parts.Add(Text["ResponseCompletionGap"] + " " + Text[JournalKey(completion.Status)]);
        }
        if (diagnostics.RuleMutation is { } mutation
            && (!mutation.Readable && !mutation.Durable || mutation.IgnoredEntries > 0 || mutation.RetainedUnsupportedEntries > 0))
        {
            parts.Add(Text.Format("ResponseRuleMutation", RuleDescription(mutation)));
        }
        if (diagnostics.AllowRollback is { } rollback)
        {
            parts.Add(Text[RollbackKey(rollback)]);
            parts.Add(Text.Format("ResponseRollbackStorage", RuleDescription(rollback.Storage)));
        }
        return string.Join(' ', parts);
    }

    private static string RuleDescription(RuleStoreResult result)
    {
        var parts = new List<string> { Text[RuleKey(result.Status)] };
        if (result.IgnoredEntries > 0)
        {
            parts.Add(Text.Format("ResponseIgnoredCount", result.IgnoredEntries));
            parts.Add(Text[result.Durable ? "ResponseIgnoredRemoved" : "ResponseIgnoredRetained"]);
        }
        if (result.RetainedUnsupportedEntries > 0)
        {
            parts.Add(Text.Format("ResponseFutureRulesCount", result.RetainedUnsupportedEntries));
            parts.Add(Text["ResponseFutureRulesInactive"]);
        }
        return string.Join(' ', parts);
    }

    // These values describe observed proof only. Inconsistent/future combinations confirm nothing.
    private static string RollbackKey(AllowRollbackDiagnostic rollback) =>
        (rollback.State, rollback.Outcome, rollback.Storage.Status) switch
        {
            (AllowRollbackState.ConfirmedAbsent, ResponseOutcome.Succeeded, RuleStoreStatus.Written)
                or (AllowRollbackState.ConfirmedAbsent, ResponseOutcome.TargetNotFound, RuleStoreStatus.TargetNotFound) => "ResponseRollbackConfirmedAbsent",
            (AllowRollbackState.ConfirmedActive, ResponseOutcome.Failed, RuleStoreStatus.WriteFailed) => "ResponseRollbackConfirmedActive",
            (AllowRollbackState.TargetChanged, ResponseOutcome.TargetChanged, RuleStoreStatus.TargetChanged) => "ResponseRollbackTargetChanged",
            _ => "ResponseRollbackUnconfirmed",
        };

    private static string JournalKey(ActionJournalWriteStatus status) => status switch
    {
        ActionJournalWriteStatus.Appended => "ResponseJournalAppended",
        ActionJournalWriteStatus.Rotated => "ResponseJournalRotated",
        ActionJournalWriteStatus.Updated => "ResponseJournalUpdated",
        ActionJournalWriteStatus.TargetNotFound => "ResponseJournalTargetNotFound",
        ActionJournalWriteStatus.Unavailable => "ResponseJournalUnavailable",
        ActionJournalWriteStatus.InvalidRecord => "ResponseJournalInvalidRecord",
        ActionJournalWriteStatus.RotationFailed => "ResponseJournalRotationFailed",
        ActionJournalWriteStatus.EvidencePreservationFailed => "ResponseJournalEvidencePreservationFailed",
        ActionJournalWriteStatus.RecoveryRequired => "ResponseJournalRecoveryRequired",
        ActionJournalWriteStatus.RetentionLimit => "ResponseJournalRetentionLimit",
        ActionJournalWriteStatus.LockTimeout => "ResponseJournalLockTimeout",
        ActionJournalWriteStatus.UnsafeLockPath => "ResponseJournalUnsafeLockPath",
        ActionJournalWriteStatus.LockUnavailable => "ResponseJournalLockUnavailable",
        ActionJournalWriteStatus.EvidenceRecoveryBlocked => "ResponseJournalEvidenceRecoveryBlocked",
        ActionJournalWriteStatus.PathTooLong => "ResponseJournalPathTooLong",
        _ => "ResponseJournalUnknown",
    };

    private static string RuleKey(RuleStoreStatus status) => status switch
    {
        RuleStoreStatus.Loaded => "ResponseRuleLoaded",
        RuleStoreStatus.Missing => "ResponseRuleMissing",
        RuleStoreStatus.Written => "ResponseRuleWritten",
        RuleStoreStatus.TargetNotFound => "ResponseRuleTargetNotFound",
        RuleStoreStatus.InvalidRule => "ResponseRuleInvalidRule",
        RuleStoreStatus.InvalidJson => "ResponseRuleInvalidJson",
        RuleStoreStatus.InvalidFormat => "ResponseRuleInvalidFormat",
        RuleStoreStatus.UnsupportedVersion => "ResponseRuleUnsupportedVersion",
        RuleStoreStatus.ByteLimit => "ResponseRuleByteLimit",
        RuleStoreStatus.RuleLimit => "ResponseRuleRuleLimit",
        RuleStoreStatus.Unavailable => "ResponseRuleUnavailable",
        RuleStoreStatus.WriteFailed => "ResponseRuleWriteFailed",
        RuleStoreStatus.LockTimeout => "ResponseRuleLockTimeout",
        RuleStoreStatus.UnsafeLockPath => "ResponseRuleUnsafeLockPath",
        RuleStoreStatus.LockUnavailable => "ResponseRuleLockUnavailable",
        RuleStoreStatus.UnsupportedIdentityCollision => "ResponseRuleUnsupportedIdentityCollision",
        RuleStoreStatus.TargetChanged => "ResponseRuleTargetChanged",
        _ => "ResponseRuleUnknown",
    };
}
