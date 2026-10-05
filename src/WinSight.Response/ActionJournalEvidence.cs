using System.Security.Cryptography;
using System.Text.Json;

using WinSight.Core;

namespace WinSight.Response;

/// <summary>Four exact bounded archives and a resumable, bounded write-ahead eviction index.</summary>
internal static class ActionJournalEvidence
{
    internal const int Slots = 4;
    internal const int MaxMetadataBytes = 8192;
    private static readonly JsonSerializerOptions ReadOptions = new() { RespectRequiredConstructorParameters = true };

    internal sealed record State(
        int Version = 1,
        long DiscardedBytes = 0,
        long DiscardedFiles = 0,
        string LossReason = "",
        bool PriorCountersUnknown = false,
        int NextSlot = 0,
        int PendingSlot = -1,
        long PendingBytes = 0,
        string? PendingSha256 = null,
        long DiscardedMetadataBytes = 0);

    internal static string SlotPath(string path, int slot) => slot == 0
        ? path + ".corrupt.jsonl" : path + $".corrupt.{slot}.jsonl";

    internal static bool Preserve(string path)
    {
        using var source = AutomaticFileAccess.TryAcquire(path);
        if (source is null || source.IsDirectory || source.Length > ActionJournalReader.MaxBytes)
        {
            return false;
        }
        var state = ReadState(path, out var unavailable, out var invalid);
        if (unavailable || invalid && !Save(path, state) || !ResumeEviction(path, ref state))
        {
            return false;
        }
        using var input = source.OpenRead();
        var digest = Convert.ToHexString(SHA256.HashData(input));
        var free = -1;
        for (var i = 0; i < Slots; i++)
        {
            using var existing = AutomaticFileAccess.TryAcquire(SlotPath(path, i), out var missing);
            if (existing is null)
            {
                if (!missing)
                {
                    return false;
                }
                if (free < 0)
                {
                    free = i;
                }
            }
            else if (!existing.IsDirectory && existing.Length == source.Length)
            {
                using var evidence = existing.OpenRead();
                if (Convert.ToHexString(SHA256.HashData(evidence)) == digest
                    && existing.IsCurrent() && source.IsCurrent())
                {
                    return true;
                }
            }
        }
        if (free < 0)
        {
            free = state.NextSlot;
            using (var victim = AutomaticFileAccess.TryAcquire(SlotPath(path, free)))
            {
                if (victim is null || victim.IsDirectory || victim.Length > ActionJournalReader.MaxBytes)
                {
                    return false;
                }
                using var bytes = victim.OpenRead();
                state = state with
                {
                    PendingSlot = free,
                    PendingBytes = victim.Length,
                    PendingSha256 = Convert.ToHexString(SHA256.HashData(bytes)),
                };
            }
            // No slot is deleted or reused before this intent is durable.
            if (!Save(path, state) || !ResumeEviction(path, ref state))
            {
                return false;
            }
        }
        return source.IsCurrent()
            && AutomaticFileAccess.TryCopyTailAtomic(path, SlotPath(path, free), ActionJournalReader.MaxBytes);
    }

    private static bool ResumeEviction(string path, ref State state)
    {
        if (state.PendingSlot < 0)
        {
            return true;
        }
        using (var victim = AutomaticFileAccess.TryAcquireForDelete(SlotPath(path, state.PendingSlot), out var missing))
        {
            if (victim is null)
            {
                if (!missing)
                {
                    return false;
                }
            }
            else
            {
                if (victim.IsDirectory || victim.Length > ActionJournalReader.MaxBytes)
                {
                    return false;
                }
                using var input = victim.OpenRead();
                var hash = Convert.ToHexString(SHA256.HashData(input));
                if (victim.Length != state.PendingBytes || hash != state.PendingSha256)
                {
                    // An external replacement is not the object approved for eviction. Leave it
                    // intact and persist that the historical accounting can no longer be complete.
                    state = state with
                    {
                        PriorCountersUnknown = true,
                        LossReason = "evidence-replaced-externally",
                        PendingSlot = -1,
                        PendingBytes = 0,
                        PendingSha256 = null,
                    };
                    return Save(path, state);
                }
                input.Dispose();
                if (!victim.TryDelete())
                {
                    return false;
                }
            }
        }
        // A crash after delete but before this write leaves the old Pending/base counters intact;
        // the next writer confirms native not-found and applies these increments exactly once.
        state = state with
        {
            DiscardedBytes = SaturatingAdd(state.DiscardedBytes, state.PendingBytes),
            DiscardedFiles = SaturatingAdd(state.DiscardedFiles, 1),
            LossReason = "evidence-budget",
            NextSlot = (state.PendingSlot + 1) % Slots,
            PendingSlot = -1,
            PendingBytes = 0,
            PendingSha256 = null,
        };
        return Save(path, state);
    }

    internal static ActionJournalSnapshot Coverage(string path, ActionJournalSnapshot snapshot)
    {
        var state = ReadState(path, out var unavailable, out var invalid);
        return snapshot with
        {
            EvidencePreserved = Enumerable.Range(0, Slots).Any(i => AutomaticFileAccess.FileExists(SlotPath(path, i))),
            DiscardedEvidenceBytes = state.DiscardedBytes,
            DiscardedEvidenceFiles = state.DiscardedFiles,
            EvidenceLossReason = state.LossReason,
            EvidenceCountersUnknown = state.PriorCountersUnknown || unavailable || invalid,
            EvidenceRecoveryPending = state.PendingSlot >= 0 || unavailable || invalid,
            DiscardedMetadataBytes = state.DiscardedMetadataBytes,
        };
    }

    private static State ReadState(string path, out bool unavailable, out bool invalid)
    {
        unavailable = false;
        invalid = false;
        using var lease = AutomaticFileAccess.TryAcquire(path + ".evidence.json", out var missing);
        if (lease is null)
        {
            unavailable = !missing;
            return new();
        }
        if (lease.IsDirectory)
        {
            unavailable = true;
            return new();
        }
        try
        {
            if (lease.Length <= MaxMetadataBytes)
            {
                using var input = lease.OpenRead();
                using var document = JsonDocument.Parse(input);
                var value = document.RootElement;
                var required = new[] { "Version", "DiscardedBytes", "DiscardedFiles", "LossReason", "PriorCountersUnknown",
                    "NextSlot", "PendingSlot", "PendingBytes", "PendingSha256" };
                var complete = value.ValueKind == JsonValueKind.Object && required.All(name => value.TryGetProperty(name, out _));
                var state = complete ? value.Deserialize<State>(ReadOptions) : null;
                if (state is not null && state.Version == 1 && state.DiscardedBytes >= 0 && state.DiscardedFiles >= 0
                    && state.DiscardedMetadataBytes >= 0 && state.NextSlot is >= 0 and < Slots
                    && state.PendingSlot is >= -1 and < Slots && state.PendingBytes >= 0
                    && state.PendingBytes <= ActionJournalReader.MaxBytes && state.LossReason is { Length: <= 128 }
                    && (state.PendingSlot < 0 || state.PendingSha256 is { Length: 64 }) && lease.IsCurrent())
                {
                    return state;
                }
            }
        }
        catch (JsonException)
        {
            // Invalid/version-unknown metadata is explicitly discarded by the next successful
            // durable writer. The unknown-prior-counters flag survives every later update.
        }
        invalid = true;
        return new State(LossReason: "invalid-evidence-metadata", PriorCountersUnknown: true,
            DiscardedMetadataBytes: lease.Length);
    }

    private static bool Save(string path, State state)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(state);
        return bytes.Length <= MaxMetadataBytes
            && AutomaticFileAccess.TryWriteAtomicBounded(path + ".evidence.json", bytes);
    }

    private static long SaturatingAdd(long left, long right) => long.MaxValue - left < right ? long.MaxValue : left + right;
}
