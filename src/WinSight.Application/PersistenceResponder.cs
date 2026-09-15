using System.Text.Json;

using WinSight.Response;

namespace WinSight.Application;

/// <summary>The live state of a persistence target: its payload to preserve, and its revalidation token.</summary>
/// <param name="Payload">Opaque bytes that let <see cref="IPersistenceMutator.Restore"/> put it back.</param>
/// <param name="RevalidationToken">The current data/command, compared against the alert's token.</param>
public sealed record PersistenceSnapshot(byte[] Payload, string RevalidationToken);

/// <summary>The OS operations a persistence action needs, behind an interface so the flow is testable.</summary>
public interface IPersistenceMutator
{
    /// <summary>Reads the target's payload and revalidation token, or null when it no longer exists.</summary>
    PersistenceSnapshot? Capture(PersistenceActionTarget target);

    /// <summary>Removes the target (delete the value, or delete the startup file). False on failure.</summary>
    bool Remove(PersistenceActionTarget target);

    /// <summary>Whether the origin is free to restore into (value absent, or file path unoccupied).</summary>
    bool OriginIsFree(PersistenceActionTarget target);

    /// <summary>Writes a captured payload back to the origin. False on failure.</summary>
    bool Restore(PersistenceActionTarget target, byte[] payload);
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
    private readonly ActionJournal _journal;
    private readonly Func<DateTimeOffset> _clock;

    public PersistenceResponder(
        IPersistenceMutator mutator,
        Quarantine? quarantine = null,
        ActionJournal? journal = null,
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
        var outcome = BlockCore(target, actionId);
        var result = new ResponseResult(actionId, ResponseActionKind.QuarantinePersistence, outcome,
            target.DisplayName, _clock(), Reversible: outcome == ResponseOutcome.Succeeded);
        _journal.TryAppend(new ActionJournalEntry(
            actionId, ResponseActionKind.QuarantinePersistence, outcome, target.DisplayName, result.AtUtc,
            result.Reversible));
        return result;
    }

    private ResponseOutcome BlockCore(PersistenceActionTarget target, Guid actionId)
    {
        var snapshot = _mutator.Capture(target);
        if (snapshot is null)
        {
            return ResponseOutcome.TargetNotFound;
        }
        if (!string.Equals(snapshot.RevalidationToken, target.RevalidationToken, StringComparison.Ordinal))
        {
            return ResponseOutcome.TargetChanged;
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
            return ResponseOutcome.Failed;
        }
        if (!_mutator.Remove(target))
        {
            // Do not keep a quarantine copy of something still live: it would restore a duplicate.
            _quarantine.Remove(item.Id);
            return ResponseOutcome.Failed;
        }
        return ResponseOutcome.Succeeded;
    }

    /// <summary>
    /// Undoes a block: writes the quarantined entry back if its origin is still free, and records the
    /// block as undone. <paramref name="blockActionId"/> is the block's action id.
    /// </summary>
    public ResponseResult Restore(Guid blockActionId)
    {
        var actionId = Guid.NewGuid();
        var (outcome, target) = RestoreCore(blockActionId);
        var result = new ResponseResult(actionId, ResponseActionKind.RestorePersistence, outcome,
            target, _clock(), Reversible: false);
        _journal.TryAppend(new ActionJournalEntry(
            actionId, ResponseActionKind.RestorePersistence, outcome, target, result.AtUtc, false));
        if (outcome == ResponseOutcome.Succeeded)
        {
            _journal.MarkUndone(blockActionId, actionId);
        }
        return result;
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
        if (!_mutator.OriginIsFree(envelope.Target))
        {
            // Something else occupies the origin now; overwriting it would destroy that instead.
            return (ResponseOutcome.TargetChanged, item.DisplayName);
        }
        if (!_mutator.Restore(envelope.Target, envelope.Payload))
        {
            return (ResponseOutcome.Failed, item.DisplayName);
        }
        _quarantine.Remove(item.Id);
        return (ResponseOutcome.Succeeded, item.DisplayName);
    }

    private sealed record QuarantineEnvelope(PersistenceActionTarget Target, byte[] Payload);
}
