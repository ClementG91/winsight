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
        var entries = new ActionJournal(journalPath).Read(max);
        var b = new ToolReport.Builder("actions");
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
        return b.Build(entries.Count == 0
            ? "no response actions recorded"
            : $"{entries.Count} recorded response action(s), newest first");
    }
}
