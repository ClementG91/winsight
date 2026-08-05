using System.ComponentModel;
using ModelContextProtocol.Server;

namespace WinSight.Mcp;

/// <summary>
/// Ready-made investigations a user can start from their MCP client's prompt menu.
/// </summary>
/// <remarks>
/// <b>These exist for the two answers that are wrong in a way the user cannot detect.</b> Server
/// instructions already carry WinSight's interpretation rules, but instructions are advisory
/// context a model may compress, reorder or lose behind a long conversation. A prompt is selected
/// deliberately by the user at the moment they ask the question, and it puts the rule in the same
/// turn as the request.
///
/// Both prompts encode a failure whose output reads as a confident, well-formed answer:
/// reporting traffic as blocked when nothing is filtering, and reporting "nobody knows who wrote
/// this" when the truth is "WinSight was not allowed to look". Neither looks like an error.
///
/// They are deliberately few. A prompt for every tool would be a menu of things the tool
/// descriptions already say, and would dilute the two that carry a real correction.
/// </remarks>
// Not a static class: the SDK's WithPrompts<T> takes a type argument, which C# forbids for one.
[McpServerPromptType]
public sealed class WinSightMcpPrompts
{
    [McpServerPrompt(Name = "winsight_triage_machine")]
    [Description(
        "Walk this Windows machine's security posture end to end and report what deserves attention, " +
        "using WinSight's read-only scanners in a sensible order.")]
    public static string TriageMachine(
        [Description("Optional focus, e.g. 'ransomware', 'network', 'startup'. Leave empty for a full sweep.")]
        string? focus = null) =>
        $"""
        Assess the security posture of this Windows machine using the WinSight tools.

        Work in this order and stop to report as soon as you have enough to answer:

        1. `winsight_overview` in summary mode. It runs the balanced set and is the cheapest complete
           picture. Do not request evidence yet.
        2. `winsight_alerts`. This is WinSight's record of what its real-time protection already
           flagged, including while nobody was at the screen. An empty journal is normal.
        3. `winsight_outbound_firewall`, for WinSight's own outbound filtering posture.
        4. Only for the areas that came back noteworthy, call `winsight_scan` with
           `includeEvidence=true` to see the individual items.
        5. If a specific process is implicated, call `winsight_process` with its pid rather than
           re-running and cross-referencing whole scanners.
        {(string.IsNullOrWhiteSpace(focus) ? "" : $"\n        The user is specifically concerned about: {focus}. Prioritise accordingly, but still run step 1 first.\n")}
        Rules for how you report, which matter more than the findings themselves:

        - A `notable` item is evidence worth investigating. It is not proof of malware, and saying so
          is not hedging; it is the accurate strength of the claim.
        - WinSight observes. It has not blocked, removed, quarantined or repaired anything. Never
          write a sentence that implies it did.
        - For the outbound firewall, `mode` is what an operator requested and `effectiveState` is what
          is running. Call traffic filtered only when `effectiveState` is `Active`. `Degraded` means
          enforcement was requested and is not filtering. When `available` is false, say WinSight
          could not verify the service — never that outbound filtering is off.
        - A persistence item can be flagged because of its command line while its file signature is
          perfectly valid. When `commandLineConcern` is present, that is the finding: a
          Windows-signed interpreter was handed a payload the signature does not cover. Report both
          halves, because "signature valid" alone reads as an all-clear.
        - If nothing is noteworthy, say that plainly. Do not manufacture concern from routine items.
        """;

    [McpServerPrompt(Name = "winsight_explain_alert")]
    [Description(
        "Explain what a WinSight real-time detection means, what the user should check, and what it " +
        "does not prove.")]
    public static string ExplainAlert(
        [Description("Optional: the specific alert to focus on. Leave empty to review the whole journal.")]
        string? alert = null) =>
        $"""
        Read WinSight's detection journal with `winsight_alerts` and explain{(
            string.IsNullOrWhiteSpace(alert) ? " what it contains" : $" this detection: {alert}")}.

        Use `includeEvidence=true` so you can see the individual entries.

        When you explain it:

        - Say what surface changed and what an attacker could achieve with it, in plain language.
        - Give the user something to do: what to check, and where in Windows to check it.
        - State what the detection does not establish. A new startup item is not proof of compromise;
          software installs startup items legitimately.
        - Never say WinSight blocked, removed or quarantined anything. It records and alerts.

        One distinction you must not collapse. An alert may name the program that wrote it
        ("written by setup.exe (pid 4242)"). When it instead says "author unknown", the reason in
        brackets is meaningful:

        - "attribution needs Administrator" means the writer could have been identified had WinSight
          been running elevated. Nothing was watching. Tell the user that re-running elevated would
          answer the question.
        - "attribution watching, no matching write seen" means something *was* watching and genuinely
          saw no matching write.

        Reporting the first as if it were the second turns "I was not allowed to look" into "nobody
        knows", which is a stronger and different claim. Repeat the bracketed reason rather than
        dropping it.
        """;
}
