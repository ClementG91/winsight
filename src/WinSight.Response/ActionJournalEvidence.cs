using System.Security.Cryptography;
using System.Text.Json;

using WinSight.Core;

namespace WinSight.Response;

/// <summary>Four exact bounded archives and a resumable, bounded write-ahead eviction index.</summary>
internal static partial class ActionJournalEvidence
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
        long DiscardedMetadataBytes = 0,
        string? DiscardedMetadataTailSha256 = null,
        long DiscardedJournalPrefixBytes = 0,
        long UnverifiedPrefixDiscardBytes = 0,
        long UnverifiedEvidenceBytes = 0,
        int PendingTrimSlot = -2,
        long PendingTrimBytes = 0,
        long PendingTrimLength = 0,
        uint PendingTrimVolume = 0,
        ulong PendingTrimFileIndex = 0,
        string? PendingTrimTailSha256 = null,
        string? PendingTrimPublishedSha256 = null);

    internal static string SlotPath(string path, int slot) => slot == 0
        ? path + ".corrupt.jsonl" : path + $".corrupt.{slot}.jsonl";

    internal static bool Preserve(string path)
    {
        if (!Maintain(path))
        {
            return false;
        }
        using var source = AutomaticFileAccess.TryAcquire(path);
        if (source is null || source.IsDirectory)
        {
            return false;
        }
        var state = ReadState(path, out var unavailable, out var invalid);
        if (unavailable || invalid && !Save(path, state) || !ResumeEviction(path, ref state))
        {
            return false;
        }
        using var input = source.OpenRead();
        input.Position = Math.Max(0, input.Length - ActionJournalReader.MaxBytes);
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
            else if (!existing.IsDirectory && existing.Length == Math.Min(source.Length, ActionJournalReader.MaxBytes))
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
                if (victim.IsDirectory)
                {
                    return false;
                }
                // A different length already disproves identity with the approved bytes. In
                // particular, do not hash an unbounded external replacement or prevent its trim.
                var matches = victim.Length == state.PendingBytes;
                if (matches)
                {
                    using var input = victim.OpenRead();
                    matches = Convert.ToHexString(SHA256.HashData(input)) == state.PendingSha256;
                }
                if (!matches)
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
            PriorCountersUnknown = state.PriorCountersUnknown
                || WouldOverflow(state.DiscardedBytes, state.PendingBytes) || WouldOverflow(state.DiscardedFiles, 1),
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
        var preserved = false;
        var evidenceUnavailable = unavailable;
        var evidenceOverBudget = false;
        for (var slot = 0; slot < Slots; slot++)
        {
            using var archive = AutomaticFileAccess.TryAcquire(SlotPath(path, slot), out var missing);
            if (archive is null)
            {
                evidenceUnavailable |= !missing;
                continue;
            }
            preserved |= !archive.IsDirectory;
            evidenceOverBudget |= archive.Length > ActionJournalReader.MaxBytes;
            if (archive.IsDirectory)
            {
                evidenceUnavailable = true;
                continue;
            }
            try
            {
                using var input = archive.OpenRead();
                evidenceUnavailable |= !archive.IsCurrent();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                evidenceUnavailable = true;
            }
        }
        return snapshot with
        {
            EvidencePreserved = preserved,
            DiscardedEvidenceBytes = state.DiscardedBytes,
            DiscardedEvidenceFiles = state.DiscardedFiles,
            EvidenceLossReason = state.LossReason,
            EvidenceCountersUnknown = state.PriorCountersUnknown || evidenceUnavailable || invalid,
            DiscardedMetadataBytes = state.DiscardedMetadataBytes,
            DiscardedMetadataTailSha256 = state.DiscardedMetadataTailSha256,
            DiscardedJournalPrefixBytes = state.DiscardedJournalPrefixBytes,
            UnverifiedPrefixDiscardBytes = state.UnverifiedPrefixDiscardBytes,
            UnverifiedEvidenceBytes = state.UnverifiedEvidenceBytes,
            PendingPrefixDiscardBytes = state.PendingTrimSlot == -1 ? state.PendingTrimBytes : 0,
            PendingEvidencePrefixDiscardBytes = state.PendingTrimSlot >= 0 ? state.PendingTrimBytes : 0,
            EvidenceUnavailable = evidenceUnavailable,
            EvidenceOverBudget = evidenceOverBudget,
            RecoveryRequired = snapshot.SourceBytes > ActionJournalReader.MaxBytes || evidenceOverBudget || evidenceUnavailable,
            EvidenceRecoveryPending = state.PendingSlot >= 0 || state.PendingTrimSlot >= -1 || evidenceUnavailable || invalid,
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
                    && (state.PendingSlot < 0 || IsHash(state.PendingSha256))
                    && TrimStateValid(value, state) && lease.IsCurrent())
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
        using var tail = lease.OpenRead();
        tail.Position = Math.Max(0, tail.Length - MaxMetadataBytes);
        return new State(LossReason: "invalid-evidence-metadata", PriorCountersUnknown: true,
            DiscardedMetadataBytes: lease.Length,
            DiscardedMetadataTailSha256: Convert.ToHexString(SHA256.HashData(tail)));
    }

    private static bool Save(string path, State state)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(state);
        return bytes.Length <= MaxMetadataBytes
            && AutomaticFileAccess.TryWriteAtomicBounded(path + ".evidence.json", bytes);
    }

    private static long SaturatingAdd(long left, long right) => long.MaxValue - left < right ? long.MaxValue : left + right;
    private static bool WouldOverflow(long left, long right) => long.MaxValue - left < right;
    private static bool IsHash(string? hash) => hash is { Length: 64 } && hash.All(char.IsAsciiHexDigit);
}
