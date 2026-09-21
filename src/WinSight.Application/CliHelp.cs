using System.Text.RegularExpressions;

namespace WinSight.Application;

/// <summary>
/// The <c>winsight --help</c> text, and the set of commands it actually documents.
/// </summary>
/// <remarks>
/// <b>Why this is not just a string in Program.cs.</b> It was, and it drifted: the <c>hijack</c>
/// scanner shipped wired into <see cref="Adapters.SnapshotCommands"/>, into the overview that
/// <c>winsight all</c> runs, into the MCP catalog and into the dashboard's tool list — and was
/// absent from <c>--help</c>. A CLI user had no way to discover a whole privilege-escalation
/// scanner, and nothing failed, because no test compared the two.
///
/// The scanner count is already pinned in several places that must move together. Rather than add
/// a fifth thing to remember, <see cref="DocumentedCommands"/> is <i>parsed back out of</i>
/// <see cref="Text"/>, so a test can assert the help covers every command the suite dispatches. A
/// new scanner without a help line now fails that test instead of shipping invisible.
/// </remarks>
public static partial class CliHelp
{
    /// <summary>
    /// The help text, with the exit-code table rendered from <see cref="CliContract"/> rather than
    /// restated.
    /// </summary>
    /// <remarks>
    /// It was restated, and the two copies had already diverged in wording. The class documentation
    /// above explains at length why the command list lives in one place; the exit codes were a
    /// second hand-maintained copy of the same kind, added later, and they drift for the same
    /// reason - one of them gets edited.
    /// </remarks>
    public static string Text { get; } = Body.Replace(
        ExitCodePlaceholder, CliContract.ExitCodeTable, StringComparison.Ordinal);

    private const string ExitCodePlaceholder = "<<exit-codes>>";

    private const string Body = """
        winsight, free, open-source security tools for Windows.

        Usage:
          winsight [persistence|av|net|dns|all]   run checks (default: all)
          winsight firewall                       list Windows Firewall rules
          winsight processes                      running processes + signatures
          winsight modules                        unsigned DLLs loaded into processes
          winsight extensions                     browser extensions + risky permissions
          winsight certs                          trusted root CAs + rogue-root signals
          winsight hosts                          hosts-file hijack / AV-block detection
          winsight input                          kernel drivers on the keyboard/mouse path
          winsight integrity                      driver signing, memory integrity, Secure Boot
          winsight drivers                        registered kernel drivers + signature verdicts
          winsight hijack                         services another program could run in place of
          winsight process <pid>                  one process: lineage, modules, connections
          winsight sign <path>                    one file: Authenticode standing + identification hashes
          winsight holders <path>                 which processes hold this file open
          winsight alerts                         alert journal: Guardian, ransomware, camera/mic, newest first
          winsight actions                        response-action history (read-only), newest first
          winsight [suspend|resume|terminate] <pid>  act on a process (needs --confirm)
          winsight rules                          allow rules in force (read-only)
          winsight [restore|revoke] <id>          undo a block or an allow (needs --confirm)
          winsight presence                       when this machine woke, and whether anyone was there
          winsight mcp                            local read-only MCP stdio server
          winsight av --watch                     live camera/mic alerts, naming the process
          winsight input --watch                  live alerts when a keyboard/mouse tap is installed
          winsight dns --watch                    live DNS queries via ETW (Administrator)
          winsight attribution --watch            who writes autostart entries (Administrator)

        Options:
          --flagged     only noteworthy items
          --unsigned    only items whose file is unsigned or untrusted
          --nonmicrosoft only items not signed by Microsoft
          --json        machine-readable output (versioned envelope, schemaVersion 1)
          --no-network  never contact VirusTotal, whatever WINSIGHT_VT_KEY is set to
          --confirm     required by every response command (process actions, restore, revoke)
          --version     print version
          --help, -h    show this help

        Maintenance (run by setup and uninstall; act on this user only, without --confirm):
          register-signature-verb     add "Check signature with WinSight" to File Explorer
          unregister-signature-verb   remove that Explorer entry
          remove-decoys               delete ransomware decoys whose content is still unchanged

        <<exit-codes>>
        """;

    /// <summary>
    /// Every command <see cref="Text"/> documents, read back out of the text itself.
    /// </summary>
    /// <remarks>
    /// Derived rather than declared on purpose: a hand-maintained second list would be one more
    /// thing to forget, which is the failure this type exists to prevent. Both forms the usage
    /// block uses are recognised — a grouped default set in brackets, and a plain
    /// <c>winsight &lt;command&gt;</c> line. <c>all</c> is dropped: it is the overview, not a scanner.
    /// </remarks>
    public static IReadOnlySet<string> DocumentedCommands { get; } = Parse();

    private static HashSet<string> Parse()
    {
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in Text.Split('\n'))
        {
            var grouped = GroupedUsage().Match(line);
            if (grouped.Success)
            {
                foreach (var name in grouped.Groups[1].Value.Split('|', StringSplitOptions.TrimEntries))
                {
                    found.Add(name);
                }
                continue;
            }
            var single = SingleUsage().Match(line);
            if (single.Success)
            {
                found.Add(single.Groups[1].Value);
            }
        }
        found.Remove("all");
        return found;
    }

    [GeneratedRegex(@"^\s*winsight\s+\[([^\]]+)\]")]
    private static partial Regex GroupedUsage();

    [GeneratedRegex(@"^\s*winsight\s+([a-z]+)")]
    private static partial Regex SingleUsage();
}
