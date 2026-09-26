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

if (CliContract.HasOption(args, "--version"))
{
    Console.WriteLine($"winsight {Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0"}");
    return 0;
}
if (CliContract.HasOption(args, "--help") || CliContract.HasOption(args, "-h"))
{
    Console.WriteLine(CliHelp.Text);
    return 0;
}

// An option WinSight does not know is a usage error, not something to ignore. `--jsonn` used to
// produce human output silently, which in a pipeline is an empty parse rather than a failure.
if (CliContract.FirstUnknownOption(args) is { } unknownOption)
{
    Console.Error.WriteLine(
        $"unknown option '{UntrustedDisplayText.Neutralize(unknownOption)}' — "
        + "run `winsight --help` for the full list");
    return CliContract.UsageError;
}

var json = CliContract.HasOption(args, "--json");
var flaggedOnly = CliContract.HasOption(args, "--flagged");
// VirusTotal enrichment is opt-in through WINSIGHT_VT_KEY, which means an environment that happens
// to carry the variable makes an otherwise local scan reach the network - and neither --help nor the
// README said so on the CLI side. --no-network is the explicit way to refuse, for a scheduled task
// or an air-gapped run where inheriting the variable would be a surprise.
var allowNetworkLookups = !CliContract.HasOption(args, "--no-network");
var command = args.FirstOrDefault(a => !a.StartsWith('-'))?.ToLowerInvariant() ?? "all";

// A second verb was silently dropped: `winsight persistence extensions` ran a persistence scan and
// said nothing about the word the operator also typed, so they got a report for a tool they had not
// asked about. `process <pid>` legitimately takes an argument and is validated on its own below.
// These verbs legitimately take an argument (a pid or a path), so a second bare word is theirs.
string[] verbsTakingAnArgument = ["process", "sign", "holders", "suspend", "resume", "terminate", "restore", "revoke"];
if (!verbsTakingAnArgument.Contains(command)
    && CliContract.ExtraVerbs(args, command) is { Count: > 0 } extraVerbs)
{
    Console.Error.WriteLine(
        $"unexpected argument '{UntrustedDisplayText.Neutralize(extraVerbs[0])}' after "
        + $"'{UntrustedDisplayText.Neutralize(command)}' — run one command at a time");
    return CliContract.UsageError;
}

// An option this verb cannot honour is a usage error too. `persistence --watch` used to run a
// one-shot scan and exit, so an operator who asked to be told when something changed got a snapshot
// and no indication that the word they typed had been dropped.
if (CliContract.FirstUnsupportedOption(args, command) is { } unsupportedOption)
{
    Console.Error.WriteLine(
        $"'{UntrustedDisplayText.Neutralize(unsupportedOption)}' is not supported by "
        + $"'{UntrustedDisplayText.Neutralize(command)}' — it works with "
        + $"{CliContract.WatchableVerbList}");
    return CliContract.UsageError;
}

// MCP owns stdout completely: no banner or CLI renderer may run in this mode.
if (command == "mcp")
{
    return await WinSightMcpHost.RunAsync();
}

// Live camera/mic monitor (OverSight-style), long-running, prints transitions.
if ((command is "av" or "avmonitor") && CliContract.HasOption(args, "--watch"))
{
    return Adapters.WatchCameraMic();
}
if (command == "attribution" && CliContract.HasOption(args, "--watch"))
{
    return Adapters.WatchAttribution();
}

if (command == "dns" && CliContract.HasOption(args, "--watch"))
{
    return Adapters.WatchDns();
}

// Live keyboard/mouse input-filter alerts: a tap being installed is reported as it happens,
// rather than only by the next `winsight input` scan.
if (command == "input" && CliContract.HasOption(args, "--watch"))
{
    return Adapters.WatchInputFilters();
}

// Manual per-user lifecycle commands for portable installs and repair. The installer uses scoped
// declarative registry entries instead; these commands remain listed under Maintenance in --help.
if (command is "register-signature-verb" or "unregister-signature-verb")
{
    return Adapters.SetSignatureVerb(register: command == "register-signature-verb");
}

// Sweeps the ransomware decoys out of the operator's folders. Called by the uninstaller, which had
// no way to do it: the installer removed its own directory and left up to eighteen files in
// Documents, Desktop, Pictures, Videos, Music and Downloads - deliberately named to be
// unrecognisable, which is what makes them work and what makes them impossible for the user to
// identify afterwards. Because the folders follow the OneDrive redirection, they had also
// synchronised to the cloud.
//
// It is the sweep the product already performs at startup, exposed for uninstall/repair and listed
// under Maintenance rather than among the scanners.
if (command == "remove-decoys")
{
    var removed = WinSight.Ransomware.CanaryManager.RemoveOrphans(
        WinSight.Ransomware.CanaryManager.DefaultDirectories());
    Console.WriteLine($"removed {removed} decoy file(s)");
    return CliContract.Clean;
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

// `sign <path>` reports one file's Authenticode standing and identification hashes, the What's Your
// Sign? entry point on the command line. Like `process`, it takes an argument and validates it here:
// the path must be an ordinary local file (a UNC or device path is refused, not opened).
if (command == "sign")
{
    var pathArgument = args.SkipWhile(a => !a.Equals("sign", StringComparison.OrdinalIgnoreCase))
        .Skip(1)
        .FirstOrDefault(a => !a.StartsWith('-'));
    if (string.IsNullOrWhiteSpace(pathArgument))
    {
        Console.Error.WriteLine("usage: winsight sign <path> [--json]");
        return CliContract.UsageError;
    }
    var signatureReport = Adapters.DescribeSignature(pathArgument);
    if (json)
    {
        ReportRenderer.RenderJson([signatureReport], Console.Out);
    }
    else
    {
        ReportRenderer.RenderText(signatureReport, Console.Out);
    }
    return signatureReport.NotableCount > 0 ? CliContract.Notable : CliContract.Clean;
}

// `holders <path>` names the processes holding a file open. Read-only, like `sign`.
if (command == "holders")
{
    var holderPath = args.SkipWhile(a => !a.Equals("holders", StringComparison.OrdinalIgnoreCase))
        .Skip(1)
        .FirstOrDefault(a => !a.StartsWith('-'));
    if (string.IsNullOrWhiteSpace(holderPath))
    {
        Console.Error.WriteLine("usage: winsight holders <path> [--json]");
        return CliContract.UsageError;
    }
    var holderReport = Adapters.DescribeHolders(holderPath);
    if (json)
    {
        ReportRenderer.RenderJson([holderReport], Console.Out);
    }
    else
    {
        ReportRenderer.RenderText(holderReport, Console.Out);
    }
    return holderReport.NotableCount > 0 ? CliContract.Notable : CliContract.Clean;
}

// The operator-confirmed process actions. Each revalidates the target, refuses protected processes
// and records the attempt; none of them runs without --confirm.
if (command is "suspend" or "resume" or "terminate")
{
    var kind = command switch
    {
        "suspend" => WinSight.Response.ResponseActionKind.SuspendProcess,
        "resume" => WinSight.Response.ResponseActionKind.ResumeProcess,
        _ => WinSight.Response.ResponseActionKind.TerminateProcess,
    };
    var pidArgument = args.SkipWhile(a => !a.Equals(command, StringComparison.OrdinalIgnoreCase))
        .Skip(1)
        .FirstOrDefault(a => !a.StartsWith('-'));
    return Adapters.RespondToProcess(kind, pidArgument, CliContract.HasOption(args, "--confirm"));
}

// Undo a decision: `restore` puts back a blocked startup item (by the block's action id), `revoke`
// removes an Allow rule (by its id). Both ids are listed by `winsight actions`; neither runs without
// --confirm.
if (command is "restore" or "revoke")
{
    var idArgument = args.SkipWhile(a => !a.Equals(command, StringComparison.OrdinalIgnoreCase))
        .Skip(1)
        .FirstOrDefault(a => !a.StartsWith('-'));
    var confirmed = CliContract.HasOption(args, "--confirm");
    return command == "restore"
        ? Adapters.RestoreBlocked(idArgument, confirmed)
        : Adapters.RevokeRule(idArgument, confirmed);
}

IReadOnlyList<ToolReport> reports;
try
{
    reports = command == "all"
        ? Adapters.RunOverview(flaggedOnly, progress: null, allowNetworkLookups)
        : [Adapters.Run(command, flaggedOnly, allowNetworkLookups)];
}
catch (ArgumentOutOfRangeException)
{
    Console.Error.WriteLine(
        $"unknown command '{UntrustedDisplayText.Neutralize(command)}' — "
        + "run `winsight --help` for the full list");
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

// Signature view filters (#unsigned / #nonMicrosoft) narrow the items after the scan, the
// TaskExplorer/KnockKnock triage. They stack with each other (AND) and with --flagged.
var viewTokens = CliContract.ViewFilterTokens(args);
if (viewTokens.Count > 0)
{
    reports = reports
        .Select(report => report with { Items = ReportItemFilter.Apply(report.Items, viewTokens) })
        .ToList();
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
