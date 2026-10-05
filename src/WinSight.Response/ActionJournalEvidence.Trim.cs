using System.Security.Cryptography;
using System.Text.Json;

using WinSight.Core;

namespace WinSight.Response;

internal static partial class ActionJournalEvidence
{
    // -2 means no operation, -1 means the main journal, 0..3 mean fixed evidence slots.
    // No persisted string is ever interpreted as a filesystem target.
    internal static bool Maintain(string path)
    {
        var state = ReadState(path, out var unavailable, out var invalid);
        if (unavailable || invalid && !Save(path, state) || !ResumeTrim(path, ref state) || !ResumeEviction(path, ref state))
        {
            return false;
        }
        for (var slot = 0; slot < Slots; slot++)
        {
            var archivePath = SlotPath(path, slot);
            long length;
            string digest;
            using (var archive = AutomaticFileAccess.TryAcquire(archivePath, out var missing))
            {
                if (archive is null)
                {
                    if (!missing)
                    {
                        return false;
                    }
                    continue;
                }
                if (archive.IsDirectory)
                {
                    return false;
                }
                length = archive.Length;
                if (length <= ActionJournalReader.MaxBytes)
                {
                    continue;
                }
                using var input = archive.OpenRead();
                input.Position = length - ActionJournalReader.MaxBytes;
                digest = Convert.ToHexString(SHA256.HashData(input));
            }
            if (!PrepareTrim(path, slot, digest)
                || !AutomaticFileAccess.TryCopyTailAtomic(archivePath, archivePath,
                    ActionJournalReader.MaxBytes, replaceExisting: true))
            {
                return false;
            }
            state = ReadState(path, out unavailable, out invalid);
            if (unavailable || invalid || !ResumeTrim(path, ref state))
            {
                return false;
            }
        }
        return true;
    }

    internal static bool PrepareTrim(string path, int slot, string publishedSha256)
    {
        if (slot is < -1 or >= Slots || !IsHash(publishedSha256))
        {
            return false;
        }
        var state = ReadState(path, out var unavailable, out var invalid);
        if (unavailable || invalid || state.PendingTrimSlot != -2)
        {
            return false;
        }
        using var source = AutomaticFileAccess.TryAcquire(TrimPath(path, slot), out var missing);
        if (source is null)
        {
            return slot == -1 && missing;
        }
        if (source.IsDirectory)
        {
            return false;
        }
        if (source.Length <= ActionJournalReader.MaxBytes)
        {
            return true;
        }
        using var input = source.OpenRead();
        input.Position = source.Length - ActionJournalReader.MaxBytes;
        var tailHash = Convert.ToHexString(SHA256.HashData(input));
        if (slot == -1 && !HasTailEvidence(path, tailHash))
        {
            return false;
        }
        state = state with
        {
            PendingTrimSlot = slot,
            PendingTrimBytes = source.Length - ActionJournalReader.MaxBytes,
            PendingTrimLength = source.Length,
            PendingTrimVolume = source.Identity.VolumeSerialNumber,
            PendingTrimFileIndex = source.Identity.FileIndex,
            PendingTrimTailSha256 = tailHash,
            PendingTrimPublishedSha256 = publishedSha256,
        };
        return source.IsCurrent() && Save(path, state);
    }

    private static bool ResumeTrim(string path, ref State state)
    {
        if (state.PendingTrimSlot < -1)
        {
            return true;
        }
        var unchanged = false;
        var published = false;
        using (var current = AutomaticFileAccess.TryAcquire(TrimPath(path, state.PendingTrimSlot), out var missing))
        {
            if (current is null)
            {
                if (!missing)
                {
                    return false;
                }
            }
            else
            {
                if (current.IsDirectory)
                {
                    return false;
                }
                using var input = current.OpenRead();
                if (current.Identity.VolumeSerialNumber == state.PendingTrimVolume
                    && current.Identity.FileIndex == state.PendingTrimFileIndex
                    && current.Length == state.PendingTrimLength)
                {
                    input.Position = current.Length - ActionJournalReader.MaxBytes;
                    unchanged = Convert.ToHexString(SHA256.HashData(input)) == state.PendingTrimTailSha256;
                }
                else if (current.Length <= ActionJournalReader.MaxBytes)
                {
                    published = Convert.ToHexString(SHA256.HashData(input)) == state.PendingTrimPublishedSha256;
                }
                if (!current.IsCurrent())
                {
                    return false;
                }
            }
        }
        var prefix = state.PendingTrimBytes;
        if (published)
        {
            var main = state.PendingTrimSlot == -1;
            var proofMissing = main && !HasTailEvidence(path, state.PendingTrimTailSha256!);
            state = state with
            {
                PriorCountersUnknown = state.PriorCountersUnknown || proofMissing
                    || WouldOverflow(main ? state.DiscardedJournalPrefixBytes : state.DiscardedBytes, prefix),
                DiscardedJournalPrefixBytes = main ? SaturatingAdd(state.DiscardedJournalPrefixBytes, prefix) : state.DiscardedJournalPrefixBytes,
                DiscardedBytes = main ? state.DiscardedBytes : SaturatingAdd(state.DiscardedBytes, prefix),
                UnverifiedEvidenceBytes = proofMissing ? SaturatingAdd(state.UnverifiedEvidenceBytes, ActionJournalReader.MaxBytes) : state.UnverifiedEvidenceBytes,
                LossReason = proofMissing ? "trim-proof-missing" : main ? "legacy-journal-byte-budget" : "legacy-evidence-byte-budget",
            };
        }
        else if (!unchanged)
        {
            // Unknown external changes are not evidence of our expected publication. Preserve an
            // explicitly unverified amount, rather than inventing an exact committed loss counter.
            state = state with
            {
                PriorCountersUnknown = true,
                UnverifiedPrefixDiscardBytes = state.PendingTrimSlot == -1
                    ? SaturatingAdd(state.UnverifiedPrefixDiscardBytes, prefix) : state.UnverifiedPrefixDiscardBytes,
                UnverifiedEvidenceBytes = state.PendingTrimSlot >= 0
                    ? SaturatingAdd(state.UnverifiedEvidenceBytes, state.PendingTrimLength) : state.UnverifiedEvidenceBytes,
                LossReason = "unexpected-trim-replacement",
            };
        }
        state = state with
        {
            PendingTrimSlot = -2,
            PendingTrimBytes = 0,
            PendingTrimLength = 0,
            PendingTrimVolume = 0,
            PendingTrimFileIndex = 0,
            PendingTrimTailSha256 = null,
            PendingTrimPublishedSha256 = null,
        };
        return Save(path, state);
    }

    private static string TrimPath(string path, int slot) => slot == -1 ? path : SlotPath(path, slot);

    private static bool HasTailEvidence(string path, string hash)
    {
        for (var slot = 0; slot < Slots; slot++)
        {
            using var archive = AutomaticFileAccess.TryAcquire(SlotPath(path, slot));
            if (archive is not { IsDirectory: false, Length: ActionJournalReader.MaxBytes })
            {
                continue;
            }
            using var input = archive.OpenRead();
            if (Convert.ToHexString(SHA256.HashData(input)) == hash && archive.IsCurrent())
            {
                return true;
            }
        }
        return false;
    }

    private static bool TrimStateValid(JsonElement value, State state)
    {
        var group = new[] { "PendingTrimSlot", "PendingTrimBytes", "PendingTrimLength", "PendingTrimVolume",
            "PendingTrimFileIndex", "PendingTrimTailSha256", "PendingTrimPublishedSha256" };
        var present = group.Count(name => value.TryGetProperty(name, out _));
        if (present != 0 && present != group.Length || state.PendingTrimSlot is < -2 or >= Slots
            || state.DiscardedJournalPrefixBytes < 0 || state.UnverifiedPrefixDiscardBytes < 0 || state.UnverifiedEvidenceBytes < 0
            || state.DiscardedMetadataTailSha256 is not null && !IsHash(state.DiscardedMetadataTailSha256))
        {
            return false;
        }
        return state.PendingTrimSlot == -2
            ? state.PendingTrimBytes == 0 && state.PendingTrimLength == 0
                && state.PendingTrimTailSha256 is null && state.PendingTrimPublishedSha256 is null
            : state.PendingTrimLength > ActionJournalReader.MaxBytes
                && state.PendingTrimBytes == state.PendingTrimLength - ActionJournalReader.MaxBytes
                && IsHash(state.PendingTrimTailSha256) && IsHash(state.PendingTrimPublishedSha256);
    }
}
