using System.Reflection;
using WinSight.Application;
using WinSight.Mcp;
using WinSight.Reporting;

// winsight, the unified suite entry point. One signed binary runs every WinSight
// tool, emitting a shared report shape as human text or the stable --json contract.
// Read-only.
//
// The command list deliberately lives in one place only, next to the dispatcher it has to
// agree with: see WinSight.Application.CliHelp. A copy here drifted once already — the
// hijack scanner shipped undiscoverable because this comment and --help were updated by
// hand and the dispatcher was not.

if (args.Contains("--version"))
{
    Console.WriteLine($"winsight {Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0"}");
    return 0;
}
if (args.Contains("--help") || args.Contains("-h"))
{
    Console.WriteLine(CliHelp.Text);
    return 0;
}

var json = args.Contains("--json");
var flaggedOnly = args.Contains("--flagged");
var command = args.FirstOrDefault(a => !a.StartsWith('-'))?.ToLowerInvariant() ?? "all";

// MCP owns stdout completely: no banner or CLI renderer may run in this mode.
if (command == "mcp")
{
    return await WinSightMcpHost.RunAsync();
}

// Live camera/mic monitor (OverSight-style), long-running, prints transitions.
if ((command is "av" or "avmonitor") && args.Contains("--watch"))
{
    return Adapters.WatchCameraMic();
}
if (command == "attribution" && args.Contains("--watch"))
{
    return Adapters.WatchAttribution();
}

if (command == "dns" && args.Contains("--watch"))
{
    return Adapters.WatchDns();
}

IReadOnlyList<ToolReport> reports;
try
{
    reports = command == "all"
        ? Adapters.RunOverview(flaggedOnly)
        : [Adapters.Run(command, flaggedOnly)];
}
catch (ArgumentOutOfRangeException)
{
    Console.Error.WriteLine(
        $"unknown command '{command}' (persistence | av | net | dns | firewall | processes | modules | extensions | certs | hosts | input | drivers | all)");
    return 2;
}

if (json)
{
    ReportRenderer.RenderJson(reports, Console.Out);
}
else
{
    for (var i = 0; i < reports.Count; i++)
    {
        if (i > 0)
        {
            Console.WriteLine();
        }
        ReportRenderer.RenderText(reports[i], Console.Out);
    }
}

// Non-zero exit when anything is noteworthy, tray/CI/automation friendly.
return reports.Sum(r => r.NotableCount) > 0 ? 1 : 0;
