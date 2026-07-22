using WinSight.Modules;
using WinSight.NetMonitor;
using WinSight.Processes;
using WinSight.Reporting;

namespace WinSight.Application;

/// <summary>
/// Renders a <see cref="ProcessInsight"/> into the shared report shape the text renderer, the JSON
/// contract and MCP all consume.
/// </summary>
/// <remarks>
/// <b>Why the rendering is separate from the pivot.</b> The pivot decides what is true; this decides
/// what is said, and that is where a correct finding turns into a misleading sentence. Two cases
/// carry the whole design: a process with nothing wrong must not read as *cleared*, and a pid that
/// is not running must not read as a quiet one — "pid 4242 has nothing wrong with it" about
/// something that does not exist is reassuring and about nothing.
///
/// <b>Why modules are counted but not listed.</b> A busy process loads hundreds, and all but a
/// handful are Microsoft-signed. Listing them makes the view unreadable and buries the outlier, so
/// the count is reported and only the unsigned ones are named — the same reasoning that grades
/// hijack findings by exploitability rather than listing every unquoted path.
/// </remarks>
public static class ProcessInsightReport
{
    public const string ToolName = "process";

    public static ToolReport Render(int pid, ProcessInsight? insight)
    {
        var builder = new ToolReport.Builder(ToolName);
        if (insight is null)
        {
            // No items at all: an empty list is the honest rendering of "there is nothing to
            // describe", where a single "looks fine" line would be a claim about a process that is
            // not there.
            return builder.Build($"pid {pid} is not running, or is not visible to this session");
        }

        AddProcess(builder, insight);
        AddLineage(builder, insight);
        AddUnsignedModules(builder, insight);
        AddExternalConnections(builder, insight);

        return builder.Build(Summarise(insight));
    }

    private static void AddProcess(ToolReport.Builder builder, ProcessInsight insight)
    {
        var process = insight.Process;
        builder.Add(
            process.Unsigned ? Severity.Notable : Severity.Info,
            $"{process.Name} (pid {process.Pid})",
            process.Path is null
                // A protected or system process exposes no image path. Saying so beats an empty
                // field, which reads as a binary that was deleted.
                ? "image path not readable from this session"
                : $"{process.Path} [{Describe(process)}]",
            new Dictionary<string, string?>
            {
                ["pid"] = process.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["name"] = process.Name,
                ["path"] = process.Path,
                ["parentPid"] = process.ParentPid.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["commandLine"] = process.CommandLine,
                ["signature"] = process.Signature.State.ToString(),
                ["signer"] = process.Signature.Signer,
            });
    }

    private static void AddLineage(ToolReport.Builder builder, ProcessInsight insight)
    {
        var parentPid = insight.Process.ParentPid;
        var detail = insight.Parent is { } parent
            ? $"started by {parent.Name} (pid {parent.Pid})"
            // Naming the pid anyway matters: a parent that has exited is the case worth chasing,
            // and an empty field reads as "no parent" rather than "the parent is gone".
            : $"started by pid {parentPid}, which is no longer running";

        builder.Add(
            Severity.Info,
            "lineage",
            insight.Children.Count == 0
                ? detail
                : $"{detail}; spawned {string.Join(", ", insight.Children.Select(child => $"{child.Name} (pid {child.Pid})"))}",
            new Dictionary<string, string?>
            {
                ["parentPid"] = parentPid.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["parentName"] = insight.Parent?.Name,
                ["parentRunning"] = (insight.Parent is not null).ToString(),
                ["children"] = insight.Children.Count == 0
                    ? null
                    : string.Join(" | ", insight.Children.Select(child => $"{child.Pid}:{child.Name}")),
            });
    }

    private static void AddUnsignedModules(ToolReport.Builder builder, ProcessInsight insight)
    {
        foreach (var module in insight.Modules.Where(module => module.Unsigned))
        {
            builder.Add(
                Severity.Notable,
                $"unsigned module {module.ModuleName}",
                $"{module.Path} [{Describe(module)}]",
                new Dictionary<string, string?>
                {
                    ["module"] = module.ModuleName,
                    ["path"] = module.Path,
                    ["signature"] = module.Signature.State.ToString(),
                    ["signer"] = module.Signature.Signer,
                });
        }
    }

    private static void AddExternalConnections(ToolReport.Builder builder, ProcessInsight insight)
    {
        foreach (var connection in insight.Connections.Where(ProcessInsight.IsEstablishedExternal))
        {
            builder.Add(
                // Reaching the outside world is not itself wrong, and a process that does it for a
                // living would otherwise flood this view with red. It is notable only when paired
                // with an identity the machine cannot vouch for, which Connection already decides.
                connection.Noteworthy ? Severity.Notable : Severity.Info,
                $"{connection.Protocol} to {connection.Remote}",
                $"{connection.Local} → {connection.Remote} [{connection.State}]",
                new Dictionary<string, string?>
                {
                    ["protocol"] = connection.Protocol,
                    ["local"] = connection.Local,
                    ["remote"] = connection.Remote,
                    ["state"] = connection.State,
                });
        }
    }

    /// <summary>
    /// One line stating what was looked at and what stood out — never silence on a clean process.
    /// </summary>
    private static string Summarise(ProcessInsight insight)
    {
        var parts = new List<string>
        {
            $"{insight.Modules.Count} module(s)",
            $"{insight.Connections.Count} connection(s)",
        };
        if (insight.UnsignedModuleCount > 0)
        {
            parts.Add($"{insight.UnsignedModuleCount} unsigned");
        }
        if (insight.EstablishedExternalCount > 0)
        {
            parts.Add($"{insight.EstablishedExternalCount} established external");
        }
        var head = $"{insight.Process.Name} (pid {insight.Process.Pid}): {string.Join(", ", parts)}";
        return insight.IsNotable ? head : $"{head}, nothing notable";
    }

    private static string Describe(ProcessInfo process) => Describe(process.Signature);

    private static string Describe(LoadedModule module) => Describe(module.Signature);

    private static string Describe(WinSight.Core.SignatureVerdict verdict) => verdict.State switch
    {
        WinSight.Core.SignatureState.SignedTrusted => verdict.Signer is null
            ? "signature valid"
            : $"signed by {verdict.Signer}",
        WinSight.Core.SignatureState.SignedUntrusted => "signed, chain not trusted",
        WinSight.Core.SignatureState.Unsigned => "unsigned",
        WinSight.Core.SignatureState.Missing => "file missing",
        // Unknown means verification could not run. Presenting it as a problem would cry wolf over
        // files WinSight simply failed to check.
        _ => "signature not verified",
    };
}
