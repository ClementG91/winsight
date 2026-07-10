using WinSight.AvMonitor;
using WinSight.NetMonitor;
using WinSight.Persistence;
using WinSight.Reporting;

// winsight — the unified suite entry point. One signed binary runs every WinSight
// tool, emitting a shared report shape as human text or the stable --json contract.
// Read-only.
//
// Usage:
//   winsight [persistence|av|net|all]   (default: all)
//   winsight ... --flagged              only noteworthy items
//   winsight ... --json                 machine-readable output (GUI/automation)

var json = args.Contains("--json");
var flaggedOnly = args.Contains("--flagged");
var command = args.FirstOrDefault(a => !a.StartsWith('-'))?.ToLowerInvariant() ?? "all";

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
    case "all":
        reports.Add(Adapters.Persistence(flaggedOnly));
        reports.Add(Adapters.CameraMic(flaggedOnly));
        reports.Add(Adapters.Connections(flaggedOnly));
        break;
    default:
        Console.Error.WriteLine($"unknown command '{command}' (persistence | av | net | all)");
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
