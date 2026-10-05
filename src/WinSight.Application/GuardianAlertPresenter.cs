using WinSight.Persistence;
using WinSight.Response;

namespace WinSight.Application;

/// <summary>Whether the operator can act on a persistence alert, and if not, why.</summary>
public enum AlertActionAvailability
{
    /// <summary>The current user can carry the action out now.</summary>
    Supported,

    /// <summary>This vector has no response action yet (services, tasks, WMI, COM).</summary>
    UnsupportedVector,

    /// <summary>The item is machine-wide; it needs the service response tier, which has not shipped.</summary>
    RequiresService,
}

/// <summary>What an alert offers the operator: its resolved target and what can be done with it.</summary>
public sealed record GuardianAlertOptions(PersistenceActionTarget? Target, AlertActionAvailability Availability)
{
    /// <summary>True when Block is offered; Allow is always offered because it only stores a rule.</summary>
    public bool CanBlock => Availability == AlertActionAvailability.Supported && Target is not null;
}

/// <summary>
/// The decision logic behind a Guardian persistence alert: what the operator may do, and carrying out
/// Allow, Block, Restore and Revoke. This is the alert window's brain, kept out of the window so it is
/// unit tested rather than only clicked, and shared with the command line so both surfaces behave alike.
/// </summary>
/// <remarks>
/// Every decision is reversible and journalled. Allow stores a rule so the same item stops raising
/// alerts, and <see cref="Revoke"/> removes it again. Block quarantines the item and then removes it,
/// only if it still matches the alert, and <see cref="Restore"/> puts it back. All four appear in
/// <c>winsight actions</c>, so no decision is invisible or permanent by accident.
/// </remarks>
public sealed class GuardianAlertPresenter
{
    private readonly PersistenceResponder _responder;
    private readonly RuleStore _rules;
    private readonly IActionJournal _journal;
    private readonly Func<DateTimeOffset> _clock;

    /// <summary>
    /// Composes the responder itself, so blocks, restores and rule changes are recorded in one journal:
    /// there is no way to build a presenter whose decisions land in two different histories.
    /// </summary>
    public GuardianAlertPresenter(
        IPersistenceMutator? mutator = null,
        Quarantine? quarantine = null,
        RuleStore? rules = null,
        IActionJournal? journal = null,
        Func<DateTimeOffset>? clock = null)
    {
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _journal = journal ?? new ActionJournal();
        _responder = new PersistenceResponder(
            mutator ?? new RegistryAndFilePersistenceMutator(), quarantine, _journal, _clock);
        _rules = rules ?? new RuleStore(clock: _clock);
    }

    /// <summary>
    /// The Allow rule that covers this entry, or null when the arrival must be announced. An entry whose
    /// vector has no actionable target can still be covered by an image rule, so this is evaluated even
    /// when Block is unavailable. The rule store fails open: an unreadable store covers nothing.
    /// </summary>
    /// <remarks>
    /// It returns the rule rather than a yes/no so the caller can record which rule silenced the arrival.
    /// The rule store is writable by anything running as this user, so a rule is not proof the operator
    /// made the decision; naming it in the journal keeps a planted rule visible and revocable.
    /// </remarks>
    public ResponseRule? SuppressingRule(AutostartEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var rule = _rules.Match(
            RuleScopeKind.Persistence,
            item: PersistenceActionResolver.Resolve(entry)?.RuleItemKey,
            imagePath: entry.ImagePath);
        return rule is { Decision: RuleDecision.Allow } ? rule : null;
    }

    /// <summary>What this alert can offer the operator.</summary>
    public static GuardianAlertOptions Describe(AutostartEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var target = PersistenceActionResolver.Resolve(entry);
        var availability = target is null ? AlertActionAvailability.UnsupportedVector
            : target.Privilege != ResponsePrivilege.CurrentUser ? AlertActionAvailability.RequiresService
            : AlertActionAvailability.Supported;
        return new GuardianAlertOptions(target, availability);
    }

    /// <summary>
    /// Records the operator's decision to stop being told about this item, and journals it. Returns the
    /// stored rule, or null when nothing could be stored (so the caller never reports an Allow that did
    /// not happen).
    /// </summary>
    public ResponseRule? Allow(AutostartEntry entry) => Allow(entry, out _);

    /// <summary>Allows with an explicit outcome and storage detail, including failed rollback.</summary>
    public ResponseRule? Allow(AutostartEntry entry, out ResponseResult result)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var target = PersistenceActionResolver.Resolve(entry);
        var rule = new ResponseRule(
            Guid.NewGuid(),
            RuleScopeKind.Persistence,
            RuleDecision.Allow,
            RuleDuration.Permanent,
            _clock(),
            Item: target?.RuleItemKey,
            // Fall back to the image path when the vector has no actionable item key, so an Allow on an
            // unsupported vector still silences that exact program rather than nothing.
            ImagePath: target is null ? entry.ImagePath : null);
        var targetDescription = $"allow {entry.Vector}/{entry.Name}";
        var prepared = Prepare(ResponseActionKind.AddRule, rule.Id, targetDescription);
        if (!prepared.Durable)
        {
            result = RuleResult(rule.Id, ResponseActionKind.AddRule, ResponseOutcome.Failed, targetDescription,
                "action was not attempted because its audit intent could not be written; " + prepared.Detail);
            return null;
        }
        var stored = _rules.Add(rule, out var storage);
        var completed = Journal(
            ResponseActionKind.AddRule,
            stored is null ? ResponseOutcome.Failed : ResponseOutcome.Succeeded,
            rule.Id,
            targetDescription,
            reversible: stored is not null);
        result = RuleResult(rule.Id, ResponseActionKind.AddRule,
            stored is null ? ResponseOutcome.Failed : ResponseOutcome.Succeeded, targetDescription,
            stored is null || storage.IgnoredEntries > 0 ? storage.Detail : null);
        if (completed.Durable || stored is null)
        {
            if (!completed.Durable)
            {
                result = result with { Detail = result.Detail + "; " + completed.Detail };
            }
            return stored;
        }
        // A suppression whose completion cannot be audited must not silently remain active. Roll it
        // back when possible. A failed atomic write after a valid read confirms the old rule remains;
        // unreadable storage cannot confirm its current activity. Prepared keeps the audit gap visible.
        var rollback = _rules.RemoveWithOutcome(rule.Id, out var rollbackStorage);
        var rolledBack = rollback is ResponseOutcome.Succeeded or ResponseOutcome.TargetNotFound;
        var activeConfirmed = !rolledBack && rollbackStorage.Status == RuleStoreStatus.WriteFailed;
        result = result with
        {
            Outcome = rolledBack ? ResponseOutcome.Failed : ResponseOutcome.PartiallyApplied,
            Reversible = activeConfirmed,
            Detail = "Allow completion could not be journalled; " + completed.Detail
                + (rolledBack ? "; the new rule is confirmed absent after rollback"
                    : activeConfirmed ? "; rollback failed and the rule remains active"
                    : "; rollback could not be verified; the rule's active state is unconfirmed; inspect winsight rules when storage is readable")
                + "; " + rollbackStorage.Detail,
        };
        return activeConfirmed ? stored : null;
    }

    /// <summary>The persistence Allow rules currently in force, so no Allow is invisible.</summary>
    public IReadOnlyList<ResponseRule> AllowRules() => _rules.ActiveRules(RuleScopeKind.Persistence);

    /// <summary>Active persistence rules plus precise store availability and ignored-entry coverage.</summary>
    public IReadOnlyList<ResponseRule> AllowRules(out RuleStoreResult result) => _rules.ActiveRules(RuleScopeKind.Persistence, out result);

    /// <summary>Removes an Allow rule, so its item alerts again. Journalled as the undo of the Allow.</summary>
    public ResponseOutcome Revoke(Guid ruleId) => Revoke(ruleId, out _);

    /// <summary>Revokes with the actual outcome and a precise audit-storage diagnostic.</summary>
    public ResponseOutcome Revoke(Guid ruleId, out ResponseResult result)
    {
        var revokeId = Guid.NewGuid();
        var target = $"rule {ruleId}";
        var prepared = Prepare(ResponseActionKind.RemoveRule, revokeId, target);
        if (!prepared.Durable)
        {
            result = RuleResult(revokeId, ResponseActionKind.RemoveRule, ResponseOutcome.Failed, target,
                "action was not attempted because its audit intent could not be written; " + prepared.Detail);
            return ResponseOutcome.Failed;
        }
        var outcome = _rules.RemoveWithOutcome(ruleId, out var storage);
        var completed = Journal(
            ResponseActionKind.RemoveRule, outcome, revokeId, target, reversible: false);
        result = RuleResult(revokeId, ResponseActionKind.RemoveRule, outcome, target,
            outcome == ResponseOutcome.Failed || storage.IgnoredEntries > 0 ? storage.Detail : null);
        if (!completed.Durable)
        {
            result = result with
            {
                Outcome = outcome == ResponseOutcome.Succeeded ? ResponseOutcome.PartiallyApplied : outcome,
                Detail = "Revoke completion could not be journalled; " + completed.Detail
                    + "; " + storage.Detail,
            };
            return result.Outcome;
        }
        if (outcome == ResponseOutcome.Succeeded)
        {
            _journal.MarkUndone(ruleId, revokeId);
        }
        return outcome;
    }

    /// <summary>Quarantines and removes the entry, if it still matches the alert.</summary>
    public ResponseResult Block(AutostartEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var options = Describe(entry);
        if (!options.CanBlock)
        {
            var refusal = options.Availability == AlertActionAvailability.RequiresService
                ? ResponseOutcome.NotAuthorized
                : ResponseOutcome.NotSupported;
            return new ResponseResult(Guid.NewGuid(), ResponseActionKind.QuarantinePersistence, refusal,
                entry.Name, _clock(), Reversible: false);
        }
        return _responder.Block(options.Target!);
    }

    /// <summary>Puts a blocked entry back, if its origin is still free. Takes the block's action id.</summary>
    public ResponseResult Restore(Guid blockActionId) => _responder.Restore(blockActionId);

    private ResponseResult RuleResult(Guid actionId, ResponseActionKind kind, ResponseOutcome outcome, string target, string? detail) =>
        new(actionId, kind, outcome, target, _clock(), Reversible: kind == ResponseActionKind.AddRule
            && outcome is ResponseOutcome.Succeeded or ResponseOutcome.PartiallyApplied, Detail: detail);

    private ActionJournalWriteResult Prepare(ResponseActionKind kind, Guid actionId, string target) =>
        _journal.TryAppendWithStatus(new ActionJournalEntry(
            actionId, kind, ResponseOutcome.AuditPrepared, target, _clock(),
            Reversible: false, Phase: ActionJournalPhase.Prepared));

    private ActionJournalWriteResult Journal(
        ResponseActionKind kind, ResponseOutcome outcome, Guid actionId, string target, bool reversible) =>
        _journal.TryAppendWithStatus(new ActionJournalEntry(
            actionId, kind, outcome, target, _clock(), reversible));
}
