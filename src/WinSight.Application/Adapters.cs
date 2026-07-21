using WinSight.AvMonitor;
using WinSight.Browser;
using WinSight.Certificates;
using WinSight.Core;
using WinSight.Firewall;
using WinSight.Hosts;
using WinSight.InputHooks;
using WinSight.Modules;
using WinSight.NetMonitor;
using WinSight.Persistence;
using WinSight.Processes;
using WinSight.Reporting;

namespace WinSight.Application;

/// <summary>
/// Maps each tool's domain results into the shared <see cref="ToolReport"/> shape.
/// The tools stay pure data producers; presentation lives here, once, so the renderer
/// (text/JSON) and a future GUI consume one contract.
/// </summary>
public static class Adapters
{
    public static IReadOnlySet<string> SnapshotCommands { get; } = new HashSet<string>(
        ["persistence", "av", "net", "dns", "firewall", "processes", "modules", "extensions", "certs", "hosts", "input"],
        StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyList<string> OverviewCommands { get; } =
        ["persistence", "av", "net", "dns", "extensions", "hosts", "certs", "input"];

    // One caching verifier shared across tools, so the same system binaries checked
    // by both persistence and connections in a single `all` run are verified once.
    // Native WinVerifyTrust first (fast, tamper-checking), catalog-aware PS fallback
    // for catalog-signed binaries, managed fallback below that, all cached.
    private static readonly ISignatureVerifier SharedVerifier =
        new CachingSignatureVerifier(new NativeSignatureVerifier());

    /// <summary>Runs one snapshot tool by its canonical CLI name.</summary>
    public static ToolReport Run(
        string command,
        bool flaggedOnly = false,
        bool allowNetworkLookups = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(command);
        cancellationToken.ThrowIfCancellationRequested();
        return command.ToLowerInvariant() switch
        {
            "persistence" => Persistence(flaggedOnly, allowNetworkLookups, cancellationToken),
            "av" or "avmonitor" => CameraMic(flaggedOnly),
            "net" or "netmonitor" => Connections(flaggedOnly, allowNetworkLookups, cancellationToken),
            "dns" => Dns(flaggedOnly),
            "firewall" or "fw" => Firewall(flaggedOnly),
            "processes" or "ps" => Processes(flaggedOnly, cancellationToken),
            "modules" or "dll" => Modules(flaggedOnly, cancellationToken),
            "extensions" or "ext" => Extensions(flaggedOnly),
            "certificates" or "certs" => Certificates(flaggedOnly),
            "hosts" => Hosts(flaggedOnly),
            "input" or "inputhooks" => InputHooks(flaggedOnly, cancellationToken),
            "alerts" => Alerts(),
            _ => throw new ArgumentOutOfRangeException(nameof(command), command, "Unknown WinSight tool."),
        };
    }

    /// <summary>
    /// Runs the balanced default overview. Process/module/firewall inventories remain
    /// explicit because they are large and would make a routine overview noisy.
    /// </summary>
    public static IReadOnlyList<ToolReport> RunOverview(
        bool flaggedOnly = false,
        IProgress<ScanProgress>? progress = null,
        bool allowNetworkLookups = true,
        CancellationToken cancellationToken = default)
    {
        var reports = new List<ToolReport>(OverviewCommands.Count);
        for (var index = 0; index < OverviewCommands.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var command = OverviewCommands[index];
            progress?.Report(new ScanProgress(index, OverviewCommands.Count, command));
            reports.Add(Run(command, flaggedOnly, allowNetworkLookups, cancellationToken));
            progress?.Report(new ScanProgress(index + 1, OverviewCommands.Count, command));
        }
        return reports;
    }

    public static ToolReport Persistence(
        bool flaggedOnly,
        bool allowNetworkLookups = true,
        CancellationToken cancellationToken = default)
    {
        var entries = new PersistenceScanner(verifier: SharedVerifier).Scan(cancellationToken);

        // Opt-in VirusTotal enrichment for the flagged, resolvable items only.
        var vt = VirusTotalEnricher.Lookup(
            entries.Where(e => e.IsSuspicious && e.ImagePath is not null).Select(e => e.ImagePath!),
            allowNetworkLookups,
            cancellationToken);

        var b = new ToolReport.Builder("persistence");
        foreach (var e in entries.Where(e => !flaggedOnly || e.IsSuspicious)
                     .OrderByDescending(e => e.IsSuspicious).ThenBy(e => e.Vector))
        {
            var report = e.ImagePath is not null && vt.TryGetValue(e.ImagePath, out var v) ? v : null;
            var displayedPath = e.ImagePath ?? e.ExpectedImagePath ?? e.Command;
            var detail = report is not null
                ? $"{displayedPath}  [VT {report.Malicious}/{report.Total}]"
                : $"{displayedPath}  [{PersistenceStatusLabel(e.Status)}]";
            b.Add(
                e.IsSuspicious ? Severity.Notable : Severity.Info,
                $"{e.Vector}/{e.Name}",
                detail,
                new Dictionary<string, string?>
                {
                    ["vector"] = e.Vector.ToString(),
                    ["name"] = e.Name,
                    ["location"] = e.Location,
                    ["command"] = e.Command,
                    ["image"] = e.ImagePath,
                    ["expectedImage"] = e.ExpectedImagePath,
                    ["fileStatus"] = e.ImageStatus.ToString(),
                    ["signature"] = e.ImageStatus == ImageResolutionStatus.Present
                        ? e.Signature.State.ToString()
                        : null,
                    ["signatureChecked"] = (e.ImageStatus == ImageResolutionStatus.Present).ToString(),
                    ["status"] = e.Status.ToString(),
                    ["signer"] = e.Signature.Signer,
                    ["vtMalicious"] = report?.Malicious.ToString(),
                    ["vtTotal"] = report?.Total.ToString(),
                    ["vtLink"] = report?.Permalink,
                });
        }
        return b.Build($"{entries.Count} autostart item(s), {entries.Count(e => e.IsSuspicious)} flagged");
    }

    private static string PersistenceStatusLabel(PersistenceStatus status) => status switch
    {
        PersistenceStatus.FileMissing => "file missing, signature not checked",
        PersistenceStatus.SignatureValid => "signature valid",
        PersistenceStatus.Unsigned => "unsigned",
        PersistenceStatus.InvalidSignature => "invalid signature",
        PersistenceStatus.AccessDenied => "access denied, signature not checked",
        _ => "verification error",
    };

    /// <summary>Runs the live camera/mic monitor, printing transitions until Ctrl+C.</summary>
    public static int WatchCameraMic()
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };
        Console.WriteLine("Watching camera/mic, Ctrl+C to stop.");
        new CameraMicMonitor().Watch(OnEvent, cts.Token);
        return 0;

        static void OnEvent(DeviceEvent e)
        {
            var device = e.Usage.Kind == DeviceKind.Webcam ? "webcam" : "mic";
            var verb = e.Kind == AvEventKind.Activated ? "ON " : "OFF";
            Console.WriteLine($"  [{verb}] {device}, {e.Usage.App}");
        }
    }

    /// <summary>Runs the live DNS (ETW) watcher, printing queries until Ctrl+C.</summary>
    public static int WatchDns()
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };
        Console.WriteLine("Watching DNS queries (ETW), Ctrl+C to stop.");
        try
        {
            new DnsEtwWatcher().Watch(
                e => Console.WriteLine($"  {e.Type,-5} {e.Name}  (pid {e.ProcessId})"), cts.Token);
            return 0;
        }
        catch (UnauthorizedAccessException)
        {
            Console.Error.WriteLine("Live DNS (ETW) requires Administrator privileges.");
            return 1;
        }
    }

    public static ToolReport CameraMic(bool flaggedOnly)
    {
        var usages = new CapabilityAccessReader().Read();
        var b = new ToolReport.Builder("camera-mic");
        foreach (var u in usages.Where(u => !flaggedOnly || u.Active).OrderByDescending(u => u.Active))
        {
            var device = u.Kind == DeviceKind.Webcam ? "webcam" : "mic";
            b.Add(
                u.Active ? Severity.Notable : Severity.Info,
                $"{device}/{u.App}",
                u.Active ? "in use now" : $"last used {u.LastStop?.ToString("u") ?? u.LastStart?.ToString("u") ?? "unknown"}",
                new Dictionary<string, string?>
                {
                    ["kind"] = device,
                    ["app"] = u.App,
                    ["packaged"] = u.Packaged.ToString(),
                    ["active"] = u.Active.ToString(),
                    ["lastStart"] = u.LastStart?.ToString("o"),
                    ["lastStop"] = u.LastStop?.ToString("o"),
                });
        }
        return b.Build($"{usages.Count} recorded use(s), {usages.Count(u => u.Active)} live now");
    }

    public static ToolReport Processes(bool flaggedOnly, CancellationToken cancellationToken = default)
    {
        var procs = new ProcessLister(SharedVerifier).Snapshot(cancellationToken);
        var b = new ToolReport.Builder("processes");
        foreach (var p in procs.Where(p => !flaggedOnly || p.Unsigned)
                     .OrderByDescending(p => p.Unsigned).ThenBy(p => p.Name, StringComparer.OrdinalIgnoreCase))
        {
            b.Add(
                p.Unsigned ? Severity.Notable : Severity.Info,
                $"{p.Name} (pid {p.Pid})",
                p.Path ?? "<no image>",
                new Dictionary<string, string?>
                {
                    ["pid"] = p.Pid.ToString(),
                    ["name"] = p.Name,
                    ["path"] = p.Path,
                    ["parentPid"] = p.ParentPid.ToString(),
                    ["commandLine"] = p.CommandLine,
                    ["signature"] = p.Signature.State.ToString(),
                    ["signer"] = p.Signature.Signer,
                });
        }
        return b.Build($"{procs.Count} process(es), {procs.Count(p => p.Unsigned)} unsigned");
    }

    /// <summary>
    /// The recorded history of real-time detections, read back from <see cref="AlertJournal"/>.
    /// </summary>
    /// <remarks>
    /// This is the one "tool" that inspects WinSight's own record rather than the machine: it is
    /// how an operator sees an alert they were not at the screen for. Windows can suppress a tray
    /// balloon outright (Focus Assist) or throttle it, so the balloon alone is not a record —
    /// this is. Every entry is <see cref="Severity.Notable"/> because everything in the journal is,
    /// by definition, something WinSight considered worth interrupting the operator for; the
    /// flagged-only filter therefore does not hide anything here.
    /// </remarks>
    public static ToolReport Alerts(int max = 200)
    {
        var alerts = AlertJournal.Read(max);
        var b = new ToolReport.Builder("alerts");
        foreach (var alert in alerts)
        {
            b.Add(
                Severity.Notable,
                $"{alert.Source}/{alert.Kind}",
                $"{alert.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} — {alert.Detail}",
                new Dictionary<string, string?>
                {
                    ["time"] = alert.TimeUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                    ["source"] = alert.Source,
                    ["kind"] = alert.Kind,
                    ["detail"] = alert.Detail,
                });
        }
        return b.Build(alerts.Count == 0
            ? "no real-time detections recorded yet"
            : $"{alerts.Count} recorded detection(s), newest first");
    }

    public static ToolReport Hosts(bool flaggedOnly)
    {
        var entries = new HostsReader().Snapshot();
        var b = new ToolReport.Builder("hosts");
        foreach (var e in entries.Where(e => !flaggedOnly || e.Notable)
                     .OrderByDescending(e => e.Notable)
                     .ThenBy(e => e.Hostname, StringComparer.OrdinalIgnoreCase))
        {
            b.Add(
                e.Notable ? Severity.Notable : Severity.Info,
                $"{e.Hostname} → {e.IpAddress}",
                e.Reason ?? "static mapping",
                new Dictionary<string, string?>
                {
                    ["hostname"] = e.Hostname,
                    ["ip"] = e.IpAddress,
                    ["reason"] = e.Reason,
                    ["isSink"] = e.IsSink.ToString(),
                    ["isSensitive"] = e.IsSensitive.ToString(),
                });
        }
        return b.Build($"{entries.Count} hosts entry(ies), {entries.Count(e => e.Notable)} flagged");
    }

    /// <summary>
    /// The kernel drivers sitting in this machine's keyboard and mouse paths — the Windows answer
    /// to a ReiKey-style "what can read my keystrokes" check.
    /// </summary>
    /// <remarks>
    /// Windows exposes no documented way to enumerate <c>SetWindowsHookEx</c> hooks, but a serious
    /// keylogger installs a filter driver on the input device stack, and those are plainly
    /// readable. Anything other than the class driver Windows installs itself is reported with its
    /// signature standing — including properly signed drivers, because a signed kernel keylogger is
    /// still a kernel keylogger and this list is one or two lines on a normal machine.
    /// </remarks>
    public static ToolReport InputHooks(bool flaggedOnly, CancellationToken cancellationToken = default)
    {
        var filters = new InputFilterScanner().Scan(cancellationToken);
        var b = new ToolReport.Builder("input");
        var notable = 0;
        foreach (var filter in filters)
        {
            var concern = InputFilterTriage.Concern(filter);
            var isNotable = InputFilterTriage.IsNotable(concern);
            if (isNotable)
            {
                notable++;
            }
            if (flaggedOnly && !isNotable)
            {
                continue;
            }
            b.Add(
                isNotable ? Severity.Notable : Severity.Info,
                $"{filter.Stack}/{filter.Name}",
                $"{filter.Position} filter — {Explain(concern)}{SignerSuffix(filter)}",
                new Dictionary<string, string?>
                {
                    ["stack"] = filter.Stack.ToString(),
                    ["position"] = filter.Position.ToString(),
                    ["name"] = filter.Name,
                    ["image"] = filter.ImagePath,
                    ["signature"] = filter.Signature.State.ToString(),
                    ["signer"] = filter.Signature.Signer,
                    ["concern"] = concern.ToString(),
                });
        }
        return b.Build($"{filters.Count} input filter(s), {notable} not installed by Windows");

        static string Explain(InputFilterConcern concern) => concern switch
        {
            InputFilterConcern.Expected => "the class driver Windows installs",
            InputFilterConcern.ThirdParty => "a third-party driver that can see every keystroke",
            InputFilterConcern.Untrusted => "UNSIGNED or untrusted, and can see every keystroke",
            _ => "listed here but its driver file is missing",
        };

        static string SignerSuffix(InputFilter filter) =>
            string.IsNullOrWhiteSpace(filter.Signature.Signer) ? string.Empty : $" (signed by {filter.Signature.Signer})";
    }

    public static ToolReport Certificates(bool flaggedOnly)
    {
        var certs = new CertStoreAuditor().Snapshot();
        var b = new ToolReport.Builder("certificates");
        foreach (var c in certs.Where(c => !flaggedOnly || c.Notable)
                     .OrderByDescending(c => c.Notable)
                     .ThenBy(c => c.Subject, StringComparer.OrdinalIgnoreCase))
        {
            b.Add(
                c.Notable ? Severity.Notable : Severity.Info,
                $"{c.Store}, {c.Subject}",
                c.Notable ? string.Join("; ", c.Risks) : $"{c.SignatureAlgorithm}, {c.KeyBits}-bit",
                new Dictionary<string, string?>
                {
                    ["store"] = c.Store,
                    ["subject"] = c.Subject,
                    ["issuer"] = c.Issuer,
                    ["thumbprint"] = c.Thumbprint,
                    ["signatureAlgorithm"] = c.SignatureAlgorithm,
                    ["keyBits"] = c.KeyBits.ToString(),
                    ["isRsa"] = c.IsRsa.ToString(),
                    ["hasPrivateKey"] = c.HasPrivateKey.ToString(),
                    ["isSelfSigned"] = c.IsSelfSigned.ToString(),
                    ["notAfter"] = c.NotAfter.ToString("o"),
                    ["risks"] = c.Risks.Count > 0 ? string.Join("; ", c.Risks) : null,
                });
        }
        return b.Build($"{certs.Count} trusted root(s), {certs.Count(c => c.Notable)} flagged");
    }

    public static ToolReport Extensions(bool flaggedOnly)
    {
        var extensions = new ExtensionScanner().Snapshot();
        var b = new ToolReport.Builder("extensions");
        foreach (var e in extensions.Where(e => !flaggedOnly || e.HighRisk)
                     .OrderByDescending(e => e.HighRisk)
                     .ThenBy(e => e.Browser, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
        {
            var perms = string.Join(", ", e.Permissions.Concat(e.HostPermissions));
            b.Add(
                e.HighRisk ? Severity.Notable : Severity.Info,
                $"{e.Browser}/{e.Name}",
                perms.Length > 0 ? perms : "(no declared permissions)",
                new Dictionary<string, string?>
                {
                    ["browser"] = e.Browser,
                    ["id"] = e.Id,
                    ["name"] = e.Name,
                    ["version"] = e.Version,
                    ["permissions"] = string.Join(" ", e.Permissions),
                    ["hostPermissions"] = string.Join(" ", e.HostPermissions),
                    ["highRisk"] = e.HighRisk.ToString(),
                    ["path"] = e.Path,
                });
        }
        return b.Build($"{extensions.Count} extension(s), {extensions.Count(e => e.HighRisk)} high-risk");
    }

    public static ToolReport Modules(bool flaggedOnly, CancellationToken cancellationToken = default)
    {
        var modules = new ModuleLister(SharedVerifier).Snapshot(cancellationToken);
        var flagged = modules.Where(m => m.Unsigned).ToList();
        var b = new ToolReport.Builder("modules");
        // The security signal is an unsigned/untrusted DLL loaded into a running
        // process (injection / search-order hijack). Listing every loaded module would
        // be pure noise, so items are the flagged modules; the summary carries totals.
        // (`--flagged` is implied here, the tool only ever reports notable modules.)
        _ = flaggedOnly;
        foreach (var m in flagged
                     .OrderBy(m => m.ProcessName, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(m => m.ModuleName, StringComparer.OrdinalIgnoreCase))
        {
            b.Add(
                Severity.Notable,
                $"{m.ProcessName} (pid {m.Pid}) ← {m.ModuleName}",
                m.Path ?? "<unknown>",
                new Dictionary<string, string?>
                {
                    ["pid"] = m.Pid.ToString(),
                    ["process"] = m.ProcessName,
                    ["module"] = m.ModuleName,
                    ["path"] = m.Path,
                    ["signature"] = m.Signature.State.ToString(),
                    ["signer"] = m.Signature.Signer,
                });
        }
        var processCount = modules.Select(m => m.Pid).Distinct().Count();
        return b.Build(
            $"{modules.Count} loaded module(s) across {processCount} process(es), {flagged.Count} unsigned");
    }

    public static ToolReport Firewall(bool flaggedOnly)
    {
        var rules = new FirewallRuleReader().Read();
        var enabled = rules.Where(r => r.Enabled).ToList();
        var b = new ToolReport.Builder("firewall");
        // Read-only rule listing (informational); --flagged shows the summary only.
        if (!flaggedOnly)
        {
            foreach (var r in enabled.OrderBy(r => r.Direction).ThenBy(r => r.DisplayName, StringComparer.OrdinalIgnoreCase))
            {
                var detail = string.Join("  ", new[] { r.Program, r.Ports }.Where(s => !string.IsNullOrEmpty(s)));
                b.Add(Severity.Info, $"{r.Direction}/{r.Action}, {r.DisplayName}", detail,
                    new Dictionary<string, string?>
                    {
                        ["name"] = r.DisplayName,
                        ["direction"] = r.Direction.ToString(),
                        ["action"] = r.Action.ToString(),
                        ["enabled"] = "True",
                        ["program"] = r.Program,
                        ["ports"] = r.Ports,
                    });
            }
        }
        return b.Build($"{rules.Count} rule(s), {enabled.Count} enabled");
    }

    public static ToolReport Dns(bool flaggedOnly)
    {
        var records = new DnsCacheReader().Read();
        var b = new ToolReport.Builder("dns");
        // DNS-cache entries are visibility, not verdicts, all informational, so
        // --flagged shows the summary only.
        if (!flaggedOnly)
        {
            foreach (var r in records.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase))
            {
                b.Add(Severity.Info, $"{r.Type} {r.Name}", r.Data,
                    new Dictionary<string, string?>
                    {
                        ["name"] = r.Name,
                        ["type"] = r.Type,
                        ["data"] = r.Data,
                        ["ttl"] = r.Ttl.ToString(),
                    });
            }
        }
        return b.Build($"{records.Count} cached DNS record(s)");
    }

    public static ToolReport Connections(
        bool flaggedOnly,
        bool allowNetworkLookups = true,
        CancellationToken cancellationToken = default)
    {
        var connections = new ConnectionMonitor(SharedVerifier).Snapshot(cancellationToken);

        // Opt-in VirusTotal enrichment for the owning binaries of noteworthy connections.
        var vt = VirusTotalEnricher.Lookup(
            connections.Where(c => c.Noteworthy && c.ImagePath is not null).Select(c => c.ImagePath!),
            allowNetworkLookups,
            cancellationToken);

        var b = new ToolReport.Builder("connections");
        foreach (var c in connections.Where(c => !flaggedOnly || c.Noteworthy)
                     .OrderByDescending(c => c.Noteworthy).ThenByDescending(c => c.External))
        {
            var report = c.ImagePath is not null && vt.TryGetValue(c.ImagePath, out var v) ? v : null;
            b.Add(
                c.Noteworthy ? Severity.Notable : Severity.Info,
                $"{c.Protocol} {c.Remote}",
                report is not null
                    ? $"{c.Process} (pid {c.Pid}), {c.State}  [VT {report.Malicious}/{report.Total}]"
                    : $"{c.Process} (pid {c.Pid}), {c.State}",
                new Dictionary<string, string?>
                {
                    ["protocol"] = c.Protocol,
                    ["local"] = c.Local,
                    ["remote"] = c.Remote,
                    ["state"] = c.State,
                    ["pid"] = c.Pid.ToString(),
                    ["process"] = c.Process,
                    ["image"] = c.ImagePath,
                    ["signature"] = c.Signature.State.ToString(),
                    ["external"] = c.External.ToString(),
                    ["vtMalicious"] = report?.Malicious.ToString(),
                    ["vtTotal"] = report?.Total.ToString(),
                    ["vtLink"] = report?.Permalink,
                });
        }
        return b.Build($"{connections.Count} connection(s), {connections.Count(c => c.Noteworthy)} noteworthy");
    }
}
