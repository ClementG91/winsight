using System.Reflection;
using WinSight.Cli;
using WinSight.Reporting;

// winsight — the unified suite entry point. One signed binary runs every WinSight
// tool, emitting a shared report shape as human text or the stable --json contract.
// Read-only.
//
// Usage:
//   winsight [persistence|av|net|dns|all]   (default: all)
//   winsight av --watch                 live camera/mic alerts (until Ctrl+C)
//   winsight ... --flagged              only noteworthy items
//   winsight ... --json                 machine-readable output (GUI/automation)

if (args.Contains("--version"))
{
    Console.WriteLine($"winsight {Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0"}");
    return 0;
}
if (args.Contains("--help") || args.Contains("-h"))
{
    Console.WriteLine("""
        winsight — free, open-source security tools for Windows.

        Usage:
          winsight [persistence|av|net|dns|all]   run checks (default: all)
          winsight av --watch                 live camera/mic alerts (Ctrl+C to stop)

        Options:
          --flagged     only noteworthy items
          --json        machine-readable output
          --version     print version
          --help, -h    show this help
        """);
    return 0;
}

var json = args.Contains("--json");
var flaggedOnly = args.Contains("--flagged");
var command = args.FirstOrDefault(a => !a.StartsWith('-'))?.ToLowerInvariant() ?? "all";

// Live camera/mic monitor (OverSight-style) — long-running, prints transitions.
if ((command is "av" or "avmonitor") && args.Contains("--watch"))
{
    return Adapters.WatchCameraMic();
}

var reports = new List<ToolReport>();
switch (command)
{
    case "persistence":
        reports.Add(Adapters.Persistence(flaggedOnly));
        break;
    case "av":
    case "avmonitor":
        reports.Add(Adapters.CameraMic(flaggedOnly));
        break;
    case "net":
    case "netmonitor":
        reports.Add(Adapters.Connections(flaggedOnly));
        break;
    case "dns":
        reports.Add(Adapters.Dns(flaggedOnly));
        break;
    case "all":
        reports.Add(Adapters.Persistence(flaggedOnly));
        reports.Add(Adapters.CameraMic(flaggedOnly));
        reports.Add(Adapters.Connections(flaggedOnly));
        reports.Add(Adapters.Dns(flaggedOnly));
        break;
    default:
        Console.Error.WriteLine($"unknown command '{command}' (persistence | av | net | dns | all)");
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

// Non-zero exit when anything is noteworthy — tray/CI/automation friendly.
return reports.Sum(r => r.NotableCount) > 0 ? 1 : 0;
