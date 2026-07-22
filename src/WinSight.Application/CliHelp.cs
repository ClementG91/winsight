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
    public const string Text = """
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
          winsight mcp                            local read-only MCP stdio server
          winsight av --watch                     live camera/mic alerts (Ctrl+C to stop)
          winsight dns --watch                    live DNS queries via ETW (Administrator)
          winsight attribution --watch            who writes autostart entries (Administrator)

        Options:
          --flagged     only noteworthy items
          --json        machine-readable output
          --version     print version
          --help, -h    show this help
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
