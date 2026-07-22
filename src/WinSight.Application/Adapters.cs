using WinSight.Attribution;
using WinSight.AvMonitor;
using WinSight.Browser;
using WinSight.Certificates;
using WinSight.CodeIntegrity;
using WinSight.Core;
using WinSight.Drivers;
using WinSight.Firewall;
using WinSight.Hijack;
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
        ["persistence", "av", "net", "dns", "firewall", "processes", "modules", "extensions", "certs", "hosts", "input", "drivers", "integrity", "hijack"],
        StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyList<string> OverviewCommands { get; } =
        ["persistence", "av", "net", "dns", "extensions", "hosts", "certs", "input", "integrity", "hijack"];

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
            "integrity" or "ci" => CodeIntegrity(flaggedOnly),
            "drivers" or "drv" => Drivers(flaggedOnly, cancellationToken),
            "hijack" or "hijacks" => Hijack(flaggedOnly, cancellationToken),
            "alerts" => Alerts(),
            _ => throw new ArgumentOutOfRangeException(nameof(command), command, "Unknown WinSight tool."),
        };
    }

    /// <summary>
    /// Runs the balanced default overview. Process, module, driver and firewall
    /// inventories remain explicit because they are large and would make a routine
    /// overview noisy.
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
        var scan = new PersistenceScanner(verifier: SharedVerifier).ScanWithCoverage(cancellationToken);
        var entries = scan.Entries;

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
        return b.Build(PersistenceSummary(entries, scan.Coverage));
    }

    /// <summary>
    /// The scan's one-line result, including what it was <b>not allowed to read</b>.
    /// </summary>
    /// <remarks>
    /// Measured on a real desktop, the same scan returned 8 546 items unelevated and 8 756
    /// elevated. The 210 missing ones were scheduled tasks — Brave, Edge, NVIDIA, OneDrive and
    /// Google updaters — and one of them was already flagged as suspicious. Nothing said so: the
    /// unelevated report read as a complete, clean scan. Naming the gap costs one clause and is the
    /// difference between "there is nothing there" and "I could not look".
    /// </remarks>
    internal static string PersistenceSummary(
        IReadOnlyList<AutostartEntry> entries, PersistenceCoverage coverage)
    {
        var line = $"{entries.Count} autostart item(s), {entries.Count(e => e.IsSuspicious)} flagged";
        if (!coverage.IsPartial)
        {
            return line;
        }
        var surfaces = string.Join(", ", coverage.UnreadableSurfaces.Distinct().Order(StringComparer.Ordinal));
        return coverage.UnreadableLocations > 0
            ? $"{line}, {coverage.UnreadableLocations} not readable without elevation ({surfaces})"
            : $"{line}, surface(s) not readable without elevation ({surfaces})";
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

    /// <summary>
    /// Runs the live write-attribution watcher, printing who writes what until Ctrl+C.
    /// </summary>
    /// <remarks>
    /// The observation vehicle for attribution: a detection says a Run key appeared, this says which
    /// program wrote it. File writes are narrowed to the startup folders, because the point is to
    /// show persistence being installed, not to print every file the machine touches.
    /// </remarks>
    public static int WatchAttribution()
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        // Shared with the dashboard rather than spelled out again here. The rule this replaced
        // compared the kernel's raw path against the full DOS folder, which cannot match once the
        // volume is spelled \Device\HarddiskVolumeN — the failure being total and silent, since a
        // startup-folder write would simply never be recorded and the watch would look quiet.
        var scope = new AttributionScope();

        Console.WriteLine("Watching registry writes and startup-folder writes (ETW), Ctrl+C to stop.");
        var attributed = 0;
        var unknownProcess = 0;
        var unresolvedTarget = 0;
        try
        {
            new WriteAttributionWatcher(scope.ShouldRecord).Watch(
                observation =>
                {
                    attributed++;
                    Console.WriteLine(
                        $"  {Path.GetFileName(observation.ExecutablePath)} (pid {observation.ProcessId})  →  {observation.Target}");
                },
                // Printed as well as counted: a watcher that only shows what it managed to attribute
                // cannot be told apart from one that is missing everything.
                miss =>
                {
                    if (miss.Reason == UnattributedReason.UnknownProcess)
                    {
                        unknownProcess++;
                        Console.WriteLine($"  [unknown process {miss.ProcessId}]  →  {miss.Target}");
                    }
                    else
                    {
                        unresolvedTarget++;
                        Console.WriteLine(miss.Target is null
                            ? $"  [unannounced key handle, pid {miss.ProcessId}]"
                            : $"  [untranslatable key, pid {miss.ProcessId}]  →  {miss.Target}");
                    }
                },
                cts.Token);
            Console.WriteLine(
                $"attributed {attributed}, unknown process {unknownProcess}, unresolved target {unresolvedTarget}");
            return 0;
        }
        catch (UnauthorizedAccessException)
        {
            Console.Error.WriteLine("Live attribution (ETW) requires Administrator privileges.");
            return 1;
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
        var findings = new HijackScanner().Scan(cancellationToken);
        var b = new ToolReport.Builder("hijack");
        foreach (var f in findings.Where(f => !flaggedOnly || f.Exposure != HijackExposure.Latent))
        {
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
                    ["exposure"] = f.Exposure.ToString(),
                    ["actionablePath"] = f.ActionablePath,
                    ["candidates"] = f.Candidates.Count == 0 ? null : string.Join(" | ", f.Candidates),
                });
        }
        var exploitable = findings.Count(f => f.Exposure != HijackExposure.Latent);
        return b.Build(findings.Count == 0
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

    public static ToolReport Hosts(bool flaggedOnly)
    {
        var snapshot = new HostsReader().Read();
        var entries = snapshot.Entries;
        var b = new ToolReport.Builder("hosts");
        // Reported as a finding, not a footnote. The hosts file is world-readable on Windows, so a
        // refusal means its permissions were changed — which is precisely what someone who has just
        // pointed a bank or an update server at their own address would do next. Rendering that as
        // "0 entries, 0 flagged" would hand them a clean bill of health.
        if (snapshot.Unreadable)
        {
            b.Add(
                Severity.Notable,
                "hosts file could not be read",
                $"{HostsReader.DefaultPath()} exists but access was denied; its contents are unknown",
                new Dictionary<string, string?>
                {
                    ["path"] = HostsReader.DefaultPath(),
                    ["unreadable"] = bool.TrueString,
                });
        }
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
        return b.Build(snapshot.Unreadable
            ? "hosts file exists but could not be read; its contents are unknown"
            : $"{entries.Count} hosts entry(ies), {entries.Count(e => e.Notable)} flagged");
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

    /// <summary>
    /// The kernel-mode drivers registered on this machine — the Windows answer to a
    /// KextViewr-style "what runs inside the kernel" check.
    /// </summary>
    /// <remarks>
    /// A driver has the same authority as Windows itself, which is why an unsigned or
    /// untrusted one is the loudest single finding WinSight produces and why a rootkit's
    /// residue shows up here. Several hundred are registered on a normal machine, so
    /// <c>--flagged</c> deliberately narrows to the two conditions nothing explains away:
    /// a signature that did not stand up, and a registration whose image is gone.
    /// </remarks>
    public static ToolReport Drivers(bool flaggedOnly, CancellationToken cancellationToken = default)
    {
        var drivers = new KernelDriverScanner(SharedVerifier).Scan(cancellationToken);
        var triaged = drivers
            .Select(driver => (Driver: driver, Concern: KernelDriverTriage.Concern(driver)))
            .ToList();
        var notable = triaged.Count(entry => KernelDriverTriage.IsNotable(entry.Concern));

        var b = new ToolReport.Builder("drivers");
        // Notable first, then earliest-loading first: a boot-start driver is running
        // before anything on the machine could have inspected it.
        foreach (var (driver, concern) in triaged
                     .Where(entry => !flaggedOnly || KernelDriverTriage.IsNotable(entry.Concern))
                     .OrderByDescending(entry => KernelDriverTriage.IsNotable(entry.Concern))
                     .ThenBy(entry => entry.Driver.Start)
                     .ThenBy(entry => entry.Driver.Name, StringComparer.OrdinalIgnoreCase))
        {
            var displayedPath = driver.ImagePath ?? driver.ExpectedImagePath ?? "<no image>";
            b.Add(
                KernelDriverTriage.IsNotable(concern) ? Severity.Notable : Severity.Info,
                $"{driver.Kind}/{driver.Name}",
                $"{displayedPath}  [{StartLabel(driver.Start)}, {Explain(concern)}{SignerSuffix(driver)}]",
                new Dictionary<string, string?>
                {
                    ["name"] = driver.Name,
                    ["kind"] = driver.Kind.ToString(),
                    ["start"] = driver.Start.ToString(),
                    ["image"] = driver.ImagePath,
                    ["expectedImage"] = driver.ExpectedImagePath,
                    ["signature"] = driver.Signature.State.ToString(),
                    ["signer"] = driver.Signature.Signer,
                    ["windowsProvided"] = driver.IsWindowsProvided.ToString(),
                    ["concern"] = concern.ToString(),
                });
        }
        return b.Build($"{drivers.Count} kernel driver(s) registered, {notable} unsigned, untrusted or orphaned");

        // Each line states what was established, not what it implies: Windows attests
        // plenty of drivers it did not write, so "signed by somebody other than Windows"
        // is the claim the evidence supports and "third-party" is not.
        static string Explain(KernelDriverConcern concern) => concern switch
        {
            KernelDriverConcern.WindowsProvided => "shipped and signed by Windows",
            KernelDriverConcern.ThirdParty => "signed by a publisher other than Windows",
            KernelDriverConcern.Untrusted => "UNSIGNED or untrusted kernel code",
            KernelDriverConcern.Unverified => "signature could not be verified",
            _ => "registered, but its image file is gone",
        };

        static string StartLabel(DriverStart start) => start switch
        {
            DriverStart.Boot => "boot start",
            DriverStart.System => "system start",
            DriverStart.Automatic => "automatic start",
            DriverStart.Manual => "on demand",
            DriverStart.Disabled => "disabled",
            _ => "start unknown",
        };

        // The full X.500 subject is kept in the fields for machine consumers; the human
        // line only needs the name the certificate was issued to.
        static string SignerSuffix(KernelDriver driver) =>
            KernelDriverTriage.SignerCommonName(driver.Signature.Signer) is { } signer
                ? $", signed by {signer}"
                : string.Empty;
    }

    /// <summary>
    /// What this machine currently enforces about the code it will run, and about its own boot
    /// chain: driver signing, test signing, memory integrity, Secure Boot, kernel debugger.
    /// </summary>
    /// <remarks>
    /// This is the scan that gives the others their meaning. "An unsigned kernel driver is
    /// registered" reads very differently on a machine in test signing, where loading unsigned
    /// drivers is the documented consequence of a setting rather than an anomaly. It is small and
    /// cheap, so it belongs in the balanced overview despite being only a handful of lines.
    /// </remarks>
    public static ToolReport CodeIntegrity(bool flaggedOnly)
    {
        var findings = CodeIntegrityTriage.Evaluate(new CodeIntegrityReader().Read());
        var b = new ToolReport.Builder("integrity");
        var notable = 0;
        foreach (var finding in findings)
        {
            var isNotable = CodeIntegrityTriage.IsNotable(finding.Concern);
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
                finding.Name,
                finding.Detail,
                new Dictionary<string, string?>
                {
                    ["protection"] = finding.Name,
                    ["concern"] = finding.Concern.ToString(),
                });
        }
        return b.Build($"{findings.Count} protection(s) checked, {notable} weakened or not enabled");
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
