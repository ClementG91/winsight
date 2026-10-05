using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using WinSight.Core;

namespace WinSight.Response;

/// <summary>Distinguishes durable writes from capacity, evidence and storage failures.</summary>
public enum ActionJournalWriteStatus
{
    Appended, Rotated, Updated, TargetNotFound, Unavailable, InvalidRecord,
    RotationFailed, EvidencePreservationFailed, RecoveryRequired, RetentionLimit,
}

public sealed record ActionJournalWriteResult(ActionJournalWriteStatus Status)
{
    public bool Durable => Status is ActionJournalWriteStatus.Appended
        or ActionJournalWriteStatus.Rotated or ActionJournalWriteStatus.Updated;

    public string Detail => $"audit storage status: {Status}; " + (Status switch
    {
        ActionJournalWriteStatus.Unavailable => "check free disk space, local-file access and sharing; retry when available",
        ActionJournalWriteStatus.EvidencePreservationFailed => "recovery evidence could not be preserved; check disk space and access, then retry",
        ActionJournalWriteStatus.RotationFailed => "atomic journal replacement failed; close conflicting file handles and retry",
        ActionJournalWriteStatus.RecoveryRequired => "bounded history migration is required; inspect winsight actions and RECOVERY.md",
        ActionJournalWriteStatus.RetentionLimit => "the requested history annotation exceeds retention budgets; annotation refused and original journal unchanged; inspect available original and undo records",
        ActionJournalWriteStatus.InvalidRecord => "the audit record is invalid; inspect the action input",
        _ => "inspect winsight actions for history coverage",
    });
}

/// <summary>Bounded serialization and exact local-file storage shared by append and undo.</summary>
internal static class ActionJournalStorage
{
    // JSON's default encoder uses at most six bytes per UTF-16 unit. 2048 units,
    // including the marker, leave over 3 KiB for the fixed record fields under
    // the 16 KiB line budget. Functional keys and quarantine data are untouched.
    private const int MaxLabelUnits = 2048;

    internal static bool Preserve(string path, string evidencePath)
    {
        // The supplied path is retained for compatibility; all evidence now shares one bounded ring.
        return string.Equals(evidencePath, path + ".corrupt.jsonl", StringComparison.OrdinalIgnoreCase)
            && ActionJournalEvidence.Preserve(path);
    }

    internal static ActionJournalWriteResult Replace(string path,
        IEnumerable<ActionJournalEntry> newestFirst, int byteBudget, int entryBudget,
        ActionJournalWriteStatus success, Guid? requiredActionId = null)
    {
        // Writer snapshots inspect at most MaxLines physical rows plus the new append. Keep the
        // newest occurrence of each phase, then budget whole available action groups. Do not
        // fabricate phases outside that bounded tail or reorder interleaved source records.
        var groups = new Dictionary<Guid, List<(int Index, ActionJournalEntry Entry)>>();
        var phases = new HashSet<(Guid Id, ActionJournalPhase Phase)>();
        var index = 0;
        foreach (var entry in newestFirst.Take(ActionJournalReader.MaxLines + 1))
        {
            if (phases.Add((entry.ActionId, entry.Phase)))
            {
                if (!groups.TryGetValue(entry.ActionId, out var group))
                {
                    group = [];
                    groups.Add(entry.ActionId, group);
                }
                group.Add((index, entry));
            }
            index++;
        }
        var records = new List<(int Index, byte[] Bytes)>();
        var total = 0;
        var requiredRetained = requiredActionId is null;
        foreach (var group in groups.Values.OrderBy(g => g[0].Index))
        {
            var candidate = new List<(int Index, byte[] Bytes)>();
            var groupBytes = 0;
            foreach (var row in group)
            {
                var bytes = Encode(row.Entry);
                if (bytes is null)
                {
                    return new(ActionJournalWriteStatus.RecoveryRequired);
                }
                candidate.Add((row.Index, bytes));
                groupBytes += bytes.Length;
            }
            if (records.Count + candidate.Count > entryBudget || (long)total + groupBytes > byteBudget)
            {
                break;
            }
            records.AddRange(candidate);
            total += groupBytes;
            requiredRetained |= group[0].Entry.ActionId == requiredActionId;
        }
        if (!requiredRetained)
        {
            // Undo is a best-effort annotation. Never publish an update that evicts its own target
            // or claim that target was durably annotated; leave the source and phases intact.
            return new(ActionJournalWriteStatus.RetentionLimit);
        }
        using var output = new MemoryStream(total);
        foreach (var record in records.OrderByDescending(r => r.Index))
        {
            output.Write(record.Bytes);
        }
        var payload = output.GetBuffer().AsSpan(0, total);
        if (!ActionJournalEvidence.PrepareTrim(path, -1, Convert.ToHexString(SHA256.HashData(payload))))
        {
            return new(ActionJournalWriteStatus.EvidencePreservationFailed);
        }
        if (!AutomaticFileAccess.TryWriteAtomicBounded(path, payload))
        {
            return new(ActionJournalWriteStatus.RotationFailed);
        }
        // Publication is durable even if a transient index failure leaves finalization pending.
        // The durable intent remains visible and the next writer resumes it before another action.
        try
        {
            _ = ActionJournalEvidence.Maintain(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            // A durable record cannot become an audit refusal because later accounting could not
            // be read. Pending remains durable and resumes when its transient storage cause clears.
        }
        return new(success);
    }

    internal static byte[]? Encode(ActionJournalEntry entry)
    {
        if (entry.Target is null
            || entry.ActionId == Guid.Empty || !Enum.IsDefined(entry.Kind)
            || !Enum.IsDefined(entry.Outcome) || !Enum.IsDefined(entry.Phase))
        {
            return null;
        }
        return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(entry with { Target = BoundLabel(entry.Target) }) + "\n");
    }

    private static string BoundLabel(string target)
    {
        if (target.Length <= MaxLabelUnits)
        {
            return target;
        }
        // Hash the complete UTF-16 units, including any malformed input, without
        // a replacement-fallback collision between distinct untrusted strings.
        var digest = Convert.ToHexString(SHA256.HashData(MemoryMarshal.AsBytes(target.AsSpan())))[..16];
        var marker = $" [truncated sha256:{digest}]";
        var cut = MaxLabelUnits - marker.Length;
        if (char.IsHighSurrogate(target[cut - 1]))
        {
            cut--;
        }
        return target[..cut] + marker;
    }
}
