using WinSight.Hijack;
using WinSight.Reporting;

namespace WinSight.Application;

public static partial class Adapters
{
    /// <summary>
    /// Services whose registered command line can be pre-empted by planting an executable earlier
    /// in the path Windows searches.
    /// </summary>
    /// <remarks>
    /// A privilege-escalation check rather than a persistence one, and the reason it belongs in a
    /// Windows tool specifically: the vector does not exist on macOS, so nothing in the
    /// Objective-See family has an equivalent. A service usually runs as SYSTEM and starts before
    /// anyone logs in, so a writable earlier candidate is a straight path from ordinary user to
    /// SYSTEM at boot.
    ///
    /// Kept in the balanced overview despite being a new tool, because it is small and specific:
    /// one finding on the machine this was written on, out of roughly seven hundred services. The
    /// large inventories (processes, modules, drivers) stay out of the overview for the opposite
    /// reason.
    /// </remarks>
    public static ToolReport Hijack(bool flaggedOnly, CancellationToken cancellationToken = default)
    {
        var scanner = new HijackScanner();
        var acquisition = scanner.ScanWithCoverage(cancellationToken);
        var findings = acquisition.Items;
        var b = new ToolReport.Builder("hijack");
        AddCoverageFinding(b, acquisition);
        if (scanner.UsedWellKnownPrincipalModel)
        {
            // Said once, as its own row, rather than folded into each finding: it qualifies every
            // "not writable" answer of the scan, including the ones that produced no row at all.
            b.Add(
                Severity.Info,
                "writability evaluated for well-known groups",
                "this process has no non-elevated token (SYSTEM, a service account or UAC off), so "
                + "directory ACLs were read for Users, Authenticated Users, Everyone and Interactive; "
                + "a grant to one named user is not seen - run unelevated for the full evaluation",
                new Dictionary<string, string?>
                {
                    ["kind"] = "evaluationMethod",
                    ["method"] = nameof(WriteAccessEvaluation.WellKnownPrincipals),
                });
        }
        foreach (var raw in findings.Where(f => !flaggedOnly || f.Exposure != HijackExposure.Latent))
        {
            // An unquoted service path's context is the service's whole registered command line,
            // arguments included, and arguments are where services keep secrets. It rode in the
            // `context` field and the detail, which MCP forwards without the sensitive-evidence gate
            // that withholds `command`. The full line now travels as `command`; the prose and
            // `context` name only the executable.
            var commandLine = raw.Kind == HijackKind.UnquotedServicePath ? raw.Context : null;
            var f = commandLine is null
                ? raw
                : raw with { Context = UnquotedPath.ExecutablePart(commandLine) ?? CommandHead(commandLine) };
            b.Add(
                // Latent is deliberately Info: unquoted paths are common, almost always sit under
                // Program Files where nobody unprivileged can plant anything, and flagging them all
                // equally would bury the one that is actually exploitable.
                f.Exposure == HijackExposure.Latent ? Severity.Info : Severity.Notable,
                $"{f.Kind}/{f.Subject}",
                HijackDetail(f),
                new Dictionary<string, string?>
                {
                    ["kind"] = f.Kind.ToString(),
                    ["subject"] = f.Subject,
                    ["context"] = f.Context,
                    ["command"] = commandLine,
                    ["exposure"] = f.Exposure.ToString(),
                    ["actionablePath"] = f.ActionablePath,
                    ["candidates"] = f.Candidates.Count == 0 ? null : string.Join(" | ", f.Candidates),
                });
        }
        var exploitable = findings.Count(f => f.Exposure != HijackExposure.Latent);
        return b.Build(!acquisition.IsComplete
            ? $"hijack scan incomplete: {acquisition.UnreadableSources} source(s) and {acquisition.UnreadableItems} item(s) unreadable"
            : findings.Count == 0
            ? "nothing found that another program could run in place of"
            : $"{findings.Count} pre-emptable configuration(s), {exploitable} exploitable now");
    }

    private static string HijackDetail(HijackFinding finding) => finding.Kind switch
    {
        HijackKind.WritableServiceDirectory =>
            $"{finding.Subject} runs from {finding.Context}, which anyone can write to: a planted DLL there loads before any other copy",
        HijackKind.WritablePathEntry =>
            $"{finding.Context}: anyone can plant into {finding.Subject}, so anything resolved by name can be answered from it",
        HijackKind.PhantomImport => finding.ActionablePath is null
            ? $"{finding.Context} imports {finding.Candidates[0]}, which no directory in its search order provides; nothing writable ahead of it today"
            : $"{finding.Context} imports {finding.Candidates[0]}, which nothing provides: anyone who can write {finding.ActionablePath}\\{finding.Candidates[0]} is loaded into it",
        _ => finding.Exposure switch
        {
            HijackExposure.Occupied =>
                $"{finding.ActionablePath} already exists and would run instead of {finding.Context}",
            HijackExposure.Exploitable =>
                $"anyone who can write {finding.ActionablePath} would run instead of {finding.Context}",
            _ => $"unquoted path; Windows would try {finding.Candidates[0]} first, but it is not writable",
        },
    };
}
