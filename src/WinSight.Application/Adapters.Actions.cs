using System.Globalization;

using WinSight.Reporting;
using WinSight.Response;

namespace WinSight.Application;

/// <summary>
/// The read-only response-action history. Kept in its own file rather than growing the main adapter:
/// this is the one place that reads the action journal, and it is deliberately incapable of performing
/// or reversing an action.
/// </summary>
public static partial class Adapters
{
    /// <summary>
    /// The response-action history: what WinSight did, when, whether it succeeded and whether it has
    /// been undone. Strictly read-only - it composes the append-only action journal and can neither
    /// perform nor reverse an action, which is why it is safe to expose wherever a scan is.
    /// </summary>
    public static ToolReport Actions() => Actions(ActionJournal.DefaultPath(), 200);

    /// <summary>
    /// Composes the action history from a named journal. Internal so tests exercise the real
    /// composition against a fixture journal instead of the operator's own.
    /// </summary>
    internal static ToolReport Actions(string journalPath, int max)
    {
        var snapshot = new ActionJournal(journalPath).ReadWithCoverage(max);
        var entries = snapshot.Entries;
        var b = new ToolReport.Builder("actions");
        var incomplete = snapshot.Unreadable || snapshot.MalformedEntries > 0 || snapshot.LimitReached
            || snapshot.EvidencePreserved || snapshot.EvidenceRecoveryPending || snapshot.EvidenceCountersUnknown
            || snapshot.DiscardedEvidenceBytes > 0 || snapshot.DiscardedMetadataBytes > 0
            || snapshot.DiscardedEvidenceFiles > 0 || snapshot.DiscardedJournalPrefixBytes > 0 || snapshot.RecoveryRequired;
        if (incomplete)
        {
            var accounting = $" Discarded journal-prefix bytes: {snapshot.DiscardedJournalPrefixBytes}; "
                + $"evidence bytes/files: {snapshot.DiscardedEvidenceBytes}/{snapshot.DiscardedEvidenceFiles}; "
                + $"metadata bytes: {snapshot.DiscardedMetadataBytes}; reason: {snapshot.EvidenceLossReason}; "
                + $"pending prefix bytes: {snapshot.PendingPrefixDiscardBytes}; "
                + $"pending evidence prefix bytes: {snapshot.PendingEvidencePrefixDiscardBytes}; "
                + $"recovery pending: {(snapshot.EvidenceRecoveryPending ? "true" : "false")}; "
                + $"unverified prefix/evidence bytes: {snapshot.UnverifiedPrefixDiscardBytes}/{snapshot.UnverifiedEvidenceBytes}; "
                + $"prior accounting: {(snapshot.EvidenceCountersUnknown ? "unknown" : "known")}.";
            b.Add(Severity.Notable, snapshot.RecoveryRequired ? "Action journal recovery required" : "Action journal coverage incomplete",
                snapshot.Unreadable ? "Action history unavailable; storage could not be read safely."
                    : (snapshot.RecoveryRequired
                        ? snapshot.EvidenceUnavailable
                            ? "Recovery evidence or metadata is unavailable; check local-file access and disk space, then retry."
                            : snapshot.EvidenceOverBudget
                                ? "Recovery evidence exceeds 16 MiB; the next response write requires automatic bounded migration."
                                : "History exceeds 16 MiB; the next response write requires automatic bounded migration."
                        : "History contains malformed records, reached a read limit, or has recovery evidence.") + accounting,
                new Dictionary<string, string?>
                {
                    ["kind"] = "actionJournalCoverage",
                    ["unreadable"] = snapshot.Unreadable ? "true" : "false",
                    ["malformedEntries"] = snapshot.MalformedEntries.ToString(CultureInfo.InvariantCulture),
                    ["limitReached"] = snapshot.LimitReached ? "true" : "false",
                    ["evidencePreserved"] = snapshot.EvidencePreserved ? "true" : "false",
                    ["evidenceRecoveryPending"] = snapshot.EvidenceRecoveryPending ? "true" : "false",
                    ["discardedEvidenceBytes"] = snapshot.DiscardedEvidenceBytes.ToString(CultureInfo.InvariantCulture),
                    ["discardedEvidenceFiles"] = snapshot.DiscardedEvidenceFiles.ToString(CultureInfo.InvariantCulture),
                    ["evidenceLossReason"] = snapshot.EvidenceLossReason,
                    ["evidenceCountersUnknown"] = snapshot.EvidenceCountersUnknown ? "true" : "false",
                    ["discardedMetadataBytes"] = snapshot.DiscardedMetadataBytes.ToString(CultureInfo.InvariantCulture),
                    ["discardedMetadataTailSha256"] = snapshot.DiscardedMetadataTailSha256,
                    ["discardedJournalPrefixBytes"] = snapshot.DiscardedJournalPrefixBytes.ToString(CultureInfo.InvariantCulture),
                    ["pendingPrefixDiscardBytes"] = snapshot.PendingPrefixDiscardBytes.ToString(CultureInfo.InvariantCulture),
                    ["pendingEvidencePrefixDiscardBytes"] = snapshot.PendingEvidencePrefixDiscardBytes.ToString(CultureInfo.InvariantCulture),
                    ["evidenceUnavailable"] = snapshot.EvidenceUnavailable ? "true" : "false",
                    ["evidenceOverBudget"] = snapshot.EvidenceOverBudget ? "true" : "false",
                    ["unverifiedPrefixDiscardBytes"] = snapshot.UnverifiedPrefixDiscardBytes.ToString(CultureInfo.InvariantCulture),
                    ["unverifiedEvidenceBytes"] = snapshot.UnverifiedEvidenceBytes.ToString(CultureInfo.InvariantCulture),
                    ["recoveryRequired"] = snapshot.RecoveryRequired ? "true" : "false",
                });
        }
        foreach (var entry in entries)
        {
            var undone = entry.UndoneByActionId is not null;
            b.Add(
                // A recorded action is history, not a finding; one that did not succeed is worth a look.
                entry.Outcome == ResponseOutcome.Succeeded ? Severity.Info : Severity.Notable,
                $"{entry.Kind} — {entry.Outcome}",
                $"{entry.AtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} — "
                    + UntrustedDisplayText.Neutralize(entry.Target)
                    + (undone ? " (undone)" : string.Empty),
                new Dictionary<string, string?>
                {
                    ["kind"] = "responseAction",
                    ["actionId"] = entry.ActionId.ToString(),
                    ["action"] = entry.Kind.ToString(),
                    ["outcome"] = entry.Outcome.ToString(),
                    ["target"] = entry.Target,
                    ["time"] = entry.AtUtc.ToString("O", CultureInfo.InvariantCulture),
                    ["reversible"] = entry.Reversible ? "true" : "false",
                    ["undoneBy"] = entry.UndoneByActionId?.ToString(),
                });
        }
        return b.Build(snapshot.Unreadable ? "response action history unavailable"
            : snapshot.RecoveryRequired ? $"{entries.Count} recorded response action(s); recovery required"
            : incomplete ? $"{entries.Count} recorded response action(s); history incomplete"
            : entries.Count == 0
            ? "no response actions recorded"
            : $"{entries.Count} recorded response action(s), newest first");
    }
}
