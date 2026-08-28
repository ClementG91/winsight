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

// An option WinSight does not know is a usage error, not something to ignore. `--jsonn` used to
// produce human output silently, which in a pipeline is an empty parse rather than a failure.
if (CliContract.FirstUnknownOption(args) is { } unknownOption)
{
    Console.Error.WriteLine(
        $"unknown option '{unknownOption}' — run `winsight --help` for the full list");
    return CliContract.UsageError;
}

var json = args.Contains("--json");
var flaggedOnly = args.Contains("--flagged");
var command = args.FirstOrDefault(a => !a.StartsWith('-'))?.ToLowerInvariant() ?? "all";

// A second verb was silently dropped: `winsight persistence extensions` ran a persistence scan and
// said nothing about the word the operator also typed, so they got a report for a tool they had not
// asked about. `process <pid>` legitimately takes an argument and is validated on its own below.
if (command != "process" && CliContract.ExtraVerbs(args, command) is { Count: > 0 } extraVerbs)
{
    Console.Error.WriteLine(
        $"unexpected argument '{extraVerbs[0]}' after '{command}' — run one command at a time");
    return CliContract.UsageError;
}

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

// Undocumented diagnostic, like the dashboard's --smoke-test: reports what the authenticated
// firewall pipe grants this caller's identity, without changing machine state. Used by the VM
// multi-user IPC gate to prove an unprivileged caller is refused a mutation. Not a scanner, so it
// is intentionally absent from the --help catalog and the snapshot dispatcher.
if (command == "firewall-ipc-selftest")
{
    return await Adapters.FirewallIpcSelfTestAsync();
}

// `process` takes an argument, so it cannot go through Adapters.Run like the snapshot scanners.
// A bad or absent pid is a usage error, reported as one rather than scanned for.
if (command == "process")
{
    var pidArgument = args.SkipWhile(a => !a.Equals("process", StringComparison.OrdinalIgnoreCase))
        .Skip(1)
        .FirstOrDefault(a => !a.StartsWith('-'));
    if (!int.TryParse(pidArgument, System.Globalization.CultureInfo.InvariantCulture, out var pid) || pid < 0)
    {
        Console.Error.WriteLine("usage: winsight process <pid>");
        return CliContract.UsageError;
    }
    var drillDown = Adapters.ProcessDrillDown(pid);
    if (json)
    {
        ReportRenderer.RenderJson([drillDown], Console.Out);
    }
    else
    {
        ReportRenderer.RenderText(drillDown, Console.Out);
    }
    return drillDown.NotableCount > 0 ? CliContract.Notable : CliContract.Clean;
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
        $"unknown command '{command}' — run `winsight --help` for the full list");
    return CliContract.UsageError;
}
catch (Exception ex) when (ex is not OperationCanceledException)
{
    // An unhandled exception used to leave the runtime to print a stack trace and choose its own
    // exit code - and under --json it produced an empty stdout, which is indistinguishable from a
    // clean machine to anything parsing the output. A scan that failed now says so, on stderr, with
    // a code that means failure rather than a finding.
    Console.Error.WriteLine($"the scan failed unexpectedly: {ex.GetType().Name}");
    return CliContract.UnexpectedFailure;
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

// Non-zero exit when anything is noteworthy, tray/CI/automation friendly. Findings stay in 0/1 so
// every existing caller keeps working; failures are 10 and above (see CliContract).
return reports.Sum(r => r.NotableCount) > 0 ? CliContract.Notable : CliContract.Clean;
