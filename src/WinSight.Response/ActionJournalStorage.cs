using System.Text;
using System.Text.Json;

using WinSight.Core;

namespace WinSight.Response;

/// <summary>Distinguishes durable writes from capacity, evidence and storage failures.</summary>
public enum ActionJournalWriteStatus
{
    Appended, Rotated, Updated, TargetNotFound, Unavailable, InvalidRecord, RecordTooLarge,
    RotationFailed, EvidencePreservationFailed, RecoveryRequired,
}

public sealed record ActionJournalWriteResult(ActionJournalWriteStatus Status)
{
    public bool Durable => Status is ActionJournalWriteStatus.Appended
        or ActionJournalWriteStatus.Rotated or ActionJournalWriteStatus.Updated;
}

/// <summary>Bounded serialization and exact local-file storage shared by append and undo.</summary>
internal static class ActionJournalStorage
{
    internal static bool Preserve(string path, string evidencePath)
    {
        using var lease = AutomaticFileAccess.TryAcquire(path);
        if (lease is null || lease.IsDirectory || lease.Length > ActionJournalReader.MaxBytes)
        {
            return false;
        }
        using var stream = lease.OpenRead();
        var bytes = new byte[(int)lease.Length];
        stream.ReadExactly(bytes);
        return lease.IsCurrent() && AutomaticFileAccess.TryCreateNewFile(evidencePath, bytes);
    }

    internal static ActionJournalWriteResult Replace(string path,
        IEnumerable<ActionJournalEntry> newestFirst, int byteBudget, int entryBudget,
        ActionJournalWriteStatus success)
    {
        var records = new List<byte[]>();
        var ids = new HashSet<Guid>();
        var total = 0;
        foreach (var entry in newestFirst)
        {
            if (!ids.Add(entry.ActionId))
            {
                continue;
            }
            var bytes = Encode(entry);
            if (bytes is null)
            {
                return new(ActionJournalWriteStatus.RecoveryRequired);
            }
            if (records.Count >= entryBudget || total + bytes.Length > byteBudget)
            {
                break;
            }
            records.Add(bytes);
            total += bytes.Length;
        }
        using var output = new MemoryStream(total);
        for (var i = records.Count - 1; i >= 0; i--)
        {
            output.Write(records[i]);
        }
        return new(AtomicFile.TryWrite(path, output.GetBuffer().AsSpan(0, total))
            ? success : ActionJournalWriteStatus.RotationFailed);
    }

    internal static byte[]? Encode(ActionJournalEntry entry)
    {
        if (entry.Target is null || entry.Target.Length > ActionJournalReader.MaxLineBytes
            || entry.ActionId == Guid.Empty || !Enum.IsDefined(entry.Kind)
            || !Enum.IsDefined(entry.Outcome) || !Enum.IsDefined(entry.Phase))
        {
            return null;
        }
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(entry) + "\n");
        return bytes.Length <= ActionJournalReader.MaxLineBytes ? bytes : null;
    }
}
