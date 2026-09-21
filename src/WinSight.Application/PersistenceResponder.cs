using System.Text.Json;

using WinSight.Response;

namespace WinSight.Application;

/// <summary>The live state of a persistence target: its payload to preserve, and its revalidation token.</summary>
/// <param name="Payload">Opaque bytes that let <see cref="IPersistenceMutator.RestoreIfFree"/> put it back.</param>
/// <param name="RevalidationToken">The current data/command, compared against the alert's token.</param>
public sealed record PersistenceSnapshot(byte[] Payload, string RevalidationToken);

/// <summary>Outcome of an atomic or transaction-backed persistence mutation.</summary>
public enum PersistenceMutationOutcome
{
    Succeeded,
    TargetNotFound,
    TargetChanged,
    AtomicityUnavailable,
    Failed,

    /// <summary>
    /// The captured object was removed, and was back by the time the removal was verified: a running
    /// program is re-creating its entry.
    /// </summary>
    Reasserted,
}

/// <summary>The OS operations a persistence action needs, behind an interface so the flow is testable.</summary>
public interface IPersistenceMutator
{
    /// <summary>Reads the target's payload and revalidation token, or null when it no longer exists.</summary>
    PersistenceSnapshot? Capture(PersistenceActionTarget target);

    /// <summary>
    /// Revalidates the exact captured payload and removes that same object. Implementations must not
    /// delete a path/value that is seen to have changed after <see cref="Capture"/>. Where the platform
    /// offers no atomic compare-and-remove (a registry value without TxR) the comparison and the
    /// removal share one handle and the result is verified; the implementation documents the window.
    /// </summary>
    PersistenceMutationOutcome RemoveIfUnchanged(
        PersistenceActionTarget target, PersistenceSnapshot expected);

    /// <summary>
    /// Restores only when the origin is free at the mutation boundary, and never overwrites an
    /// occupant it can see. Where the platform offers no atomic create-if-absent the check and the
    /// write share one handle and the write is verified; the implementation documents the window.
    /// </summary>
    PersistenceMutationOutcome RestoreIfFree(PersistenceActionTarget target, byte[] payload);
}

/// <summary>
/// Blocks or restores a persistence entry from an alert, reversibly: it revalidates the entry against
/// the alert, quarantines what it removes, and can put it back. Block is a quarantine-then-remove;
/// restore is a collision-checked write-back. Every step is journalled.
/// </summary>
/// <remarks>
/// Reversibility is the safety property: WinSight removes a startup item only after storing enough to
/// recreate it, and restore refuses if the origin is occupied again (a different item now lives
/// there). Revalidation refuses to act when the entry changed since the alert - the same discipline
/// the process responder and the decoy cleanup use. One handle identifies a block end to end: the
/// block's action id, which <c>winsight actions</c> shows and <see cref="Restore"/> accepts.
/// </remarks>
public sealed class PersistenceResponder
{
    private readonly IPersistenceMutator _mutator;
    private readonly Quarantine _quarantine;
    private readonly IActionJournal _journal;
    private readonly Func<DateTimeOffset> _clock;

    public PersistenceResponder(
        IPersistenceMutator mutator,
        Quarantine? quarantine = null,
        IActionJournal? journal = null,
        Func<DateTimeOffset>? clock = null)
    {
        _mutator = mutator ?? throw new ArgumentNullException(nameof(mutator));
        _quarantine = quarantine ?? new Quarantine();
        _journal = journal ?? new ActionJournal();
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Quarantines and removes the entry, if it still matches the alert. On success the result's
    /// <see cref="ResponseResult.ActionId"/> is the handle that <see cref="Restore"/> takes to undo it.
    /// </summary>
    public ResponseResult Block(PersistenceActionTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        var actionId = Guid.NewGuid();
        var preparedAt = _clock();
        if (!TryPrepare(actionId, ResponseActionKind.QuarantinePersistence, target.DisplayName, preparedAt))
        {
            return AuditUnavailable(actionId, ResponseActionKind.QuarantinePersistence,
                target.DisplayName, preparedAt);
        }
        var (outcome, detail) = BlockCore(target, actionId);
        var result = new ResponseResult(actionId, ResponseActionKind.QuarantinePersistence, outcome,
            target.DisplayName, _clock(),
            Reversible: outcome is ResponseOutcome.Succeeded or ResponseOutcome.PartiallyApplied,
            Detail: detail);
        return CompleteOrExposeGap(result);
    }

    /// <summary>What the operator is told when a blocked entry comes straight back.</summary>
    public const string ReassertedDetail =
        "the entry was removed and quarantined, but it was re-created immediately: a running program "
        + "is re-asserting it, so deal with that program before blocking again";

    private (ResponseOutcome Outcome, string? Detail) BlockCore(PersistenceActionTarget target, Guid actionId)
    {
        var snapshot = _mutator.Capture(target);
        if (snapshot is null)
        {
            return (ResponseOutcome.TargetNotFound, null);
        }
        if (!string.Equals(snapshot.RevalidationToken, target.RevalidationToken, StringComparison.Ordinal))
        {
            return (ResponseOutcome.TargetChanged, null);
        }
        var kind = target.Kind == PersistenceActionKind.RegistryValue
            ? QuarantineItemKind.RegistryValue
            : QuarantineItemKind.File;
        var origin = target.Kind == PersistenceActionKind.RegistryValue
            ? $"{target.Hive}\\{target.SubKey}\\{target.ValueName}"
            : target.FilePath ?? string.Empty;
        var envelope = JsonSerializer.SerializeToUtf8Bytes(new QuarantineEnvelope(target, snapshot.Payload));
        var item = _quarantine.Store(kind, origin, target.DisplayName, actionId, envelope, _clock());
        if (item is null)
        {
            return (ResponseOutcome.Failed, null);
        }
        var removal = _mutator.RemoveIfUnchanged(target, snapshot);
        if (removal == PersistenceMutationOutcome.Reasserted)
        {
            // The copy stays: it is exactly what was removed, and the evidence of what came back.
            // A restore refuses while the origin is occupied, so it cannot create a duplicate.
            return (ResponseOutcome.PartiallyApplied, ReassertedDetail);
        }
        if (removal != PersistenceMutationOutcome.Succeeded)
        {
            // Do not keep a quarantine copy of something still live: it would restore a duplicate.
            _quarantine.Remove(item.Id);
            return (Map(removal), null);
        }
        return (ResponseOutcome.Succeeded, null);
    }

    /// <summary>
    /// Undoes a block: writes the quarantined entry back if its origin is still free, and records the
    /// block as undone. <paramref name="blockActionId"/> is the block's action id.
    /// </summary>
    public ResponseResult Restore(Guid blockActionId)
    {
        var actionId = Guid.NewGuid();
        var preparedAt = _clock();
        var preparedTarget = blockActionId.ToString();
        if (!TryPrepare(actionId, ResponseActionKind.RestorePersistence, preparedTarget, preparedAt))
        {
            return AuditUnavailable(actionId, ResponseActionKind.RestorePersistence,
                preparedTarget, preparedAt);
        }
        var (outcome, target) = RestoreCore(blockActionId);
        var result = new ResponseResult(actionId, ResponseActionKind.RestorePersistence, outcome,
            target, _clock(), Reversible: false);
        var completed = _journal.TryAppend(new ActionJournalEntry(
            actionId, ResponseActionKind.RestorePersistence, outcome, target, result.AtUtc, false));
        if (outcome == ResponseOutcome.Succeeded && completed)
        {
            _journal.MarkUndone(blockActionId, actionId);
        }
        return completed ? result : ExposeCompletionGap(result);
    }

    private bool TryPrepare(
        Guid actionId, ResponseActionKind kind, string target, DateTimeOffset atUtc) =>
        _journal.TryAppend(new ActionJournalEntry(
            actionId, kind, ResponseOutcome.AuditPrepared, target, atUtc,
            Reversible: false, Phase: ActionJournalPhase.Prepared));

    private static ResponseResult AuditUnavailable(
        Guid actionId, ResponseActionKind kind, string target, DateTimeOffset atUtc) =>
        new(actionId, kind, ResponseOutcome.Failed, target, atUtc, Reversible: false,
            Detail: "action was not attempted because its audit intent could not be written");

    private ResponseResult CompleteOrExposeGap(ResponseResult result) =>
        _journal.TryAppend(new ActionJournalEntry(
            result.ActionId, result.Kind, result.Outcome, result.Target, result.AtUtc, result.Reversible))
            ? result
            : ExposeCompletionGap(result);

    private static ResponseResult ExposeCompletionGap(ResponseResult result)
    {
        var applied = result.Outcome is ResponseOutcome.Succeeded or ResponseOutcome.PartiallyApplied;
        return result with
        {
            Outcome = applied ? ResponseOutcome.PartiallyApplied : result.Outcome,
            Detail = applied
                ? "the action may have changed the target, but its completion could not be journalled"
                : "the refusal/failure completion could not be journalled",
        };
    }

    private (ResponseOutcome Outcome, string Target) RestoreCore(Guid blockActionId)
    {
        var item = _quarantine.List().FirstOrDefault(candidate => candidate.ActionId == blockActionId);
        if (item is null)
        {
            return (ResponseOutcome.TargetNotFound, blockActionId.ToString());
        }
        var payload = _quarantine.ReadPayload(item);
        if (payload is null)
        {
            return (ResponseOutcome.Failed, item.DisplayName);
        }
        QuarantineEnvelope? envelope;
        try
        {
            envelope = JsonSerializer.Deserialize<QuarantineEnvelope>(payload);
        }
        catch (JsonException)
        {
            return (ResponseOutcome.Failed, item.DisplayName);
        }
        if (envelope is null)
        {
            return (ResponseOutcome.Failed, item.DisplayName);
        }
        var restoration = _mutator.RestoreIfFree(envelope.Target, envelope.Payload);
        if (restoration != PersistenceMutationOutcome.Succeeded)
        {
            return (Map(restoration), item.DisplayName);
        }
        _quarantine.Remove(item.Id);
        return (ResponseOutcome.Succeeded, item.DisplayName);
    }

    private static ResponseOutcome Map(PersistenceMutationOutcome outcome) => outcome switch
    {
        PersistenceMutationOutcome.Succeeded => ResponseOutcome.Succeeded,
        PersistenceMutationOutcome.TargetNotFound => ResponseOutcome.TargetNotFound,
        PersistenceMutationOutcome.TargetChanged => ResponseOutcome.TargetChanged,
        PersistenceMutationOutcome.AtomicityUnavailable => ResponseOutcome.NotSupported,
        _ => ResponseOutcome.Failed,
    };

    private sealed record QuarantineEnvelope(PersistenceActionTarget Target, byte[] Payload);
}
