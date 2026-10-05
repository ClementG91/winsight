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
    RotationFailed, EvidencePreservationFailed, RecoveryRequired,
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
        return new(AutomaticFileAccess.TryWriteAtomicBounded(path, output.GetBuffer().AsSpan(0, total))
            ? success : ActionJournalWriteStatus.RotationFailed);
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
