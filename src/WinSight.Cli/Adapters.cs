using WinSight.AvMonitor;
using WinSight.Browser;
using WinSight.Certificates;
using WinSight.Core;
using WinSight.Firewall;
using WinSight.Hosts;
using WinSight.Modules;
using WinSight.NetMonitor;
using WinSight.Persistence;
using WinSight.Processes;
using WinSight.Reporting;

namespace WinSight.Cli;

/// <summary>
/// Maps each tool's domain results into the shared <see cref="ToolReport"/> shape.
/// The tools stay pure data producers; presentation lives here, once, so the renderer
/// (text/JSON) and a future GUI consume one contract.
/// </summary>
internal static class Adapters
{
    // One caching verifier shared across tools, so the same system binaries checked
    // by both persistence and connections in a single `all` run are verified once.
    // Native WinVerifyTrust first (fast, tamper-checking), catalog-aware PS fallback
    // for catalog-signed binaries, managed fallback below that — all cached.
    private static readonly ISignatureVerifier SharedVerifier =
        new CachingSignatureVerifier(new NativeSignatureVerifier());

    public static ToolReport Persistence(bool flaggedOnly)
    {
        var entries = new PersistenceScanner(verifier: SharedVerifier).Scan();

        // Opt-in VirusTotal enrichment for the flagged, resolvable items only.
        var vt = VtLookups(entries.Where(e => e.IsSuspicious && e.ImagePath is not null)
            .Select(e => e.ImagePath!));

        var b = new ToolReport.Builder("persistence");
        foreach (var e in entries.Where(e => !flaggedOnly || e.IsSuspicious)
                     .OrderByDescending(e => e.IsSuspicious).ThenBy(e => e.Vector))
        {
            var report = e.ImagePath is not null && vt.TryGetValue(e.ImagePath, out var v) ? v : null;
            b.Add(
                e.IsSuspicious ? Severity.Notable : Severity.Info,
                $"{e.Vector}/{e.Name}",
                report is not null ? $"{e.ImagePath}  [VT {report.Malicious}/{report.Total}]" : e.ImagePath ?? e.Command,
                new Dictionary<string, string?>
                {
                    ["vector"] = e.Vector.ToString(),
                    ["name"] = e.Name,
                    ["location"] = e.Location,
                    ["command"] = e.Command,
                    ["image"] = e.ImagePath,
                    ["signature"] = e.Signature.State.ToString(),
                    ["signer"] = e.Signature.Signer,
                    ["vtMalicious"] = report?.Malicious.ToString(),
                    ["vtTotal"] = report?.Total.ToString(),
                    ["vtLink"] = report?.Permalink,
                });
        }
        return b.Build($"{entries.Count} autostart item(s), {entries.Count(e => e.IsSuspicious)} flagged");
    }

    // VirusTotal lookups for the given image paths — opt-in (WINSIGHT_VT_KEY) and
    // capped to stay within the free-tier rate limit. Empty when no key is set (the
    // tool stays local-only unless the user provides their own key).
    private static IReadOnlyDictionary<string, VtVerdict> VtLookups(IEnumerable<string> imagePaths)
    {
        var results = new Dictionary<string, VtVerdict>(StringComparer.OrdinalIgnoreCase);
        var apiKey = Environment.GetEnvironmentVariable("WINSIGHT_VT_KEY");
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return results;
        }
        var client = new VirusTotalClient(apiKey);
        const int cap = 8;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in imagePaths.Where(p => seen.Add(p)).Take(cap))
        {
            if (HashUtil.Sha256File(path) is { } sha && client.Lookup(sha) is { } verdict)
            {
                results[path] = verdict;
            }
        }
        return results;
    }

    /// <summary>Runs the live camera/mic monitor, printing transitions until Ctrl+C.</summary>
    public static int WatchCameraMic()
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };
        Console.WriteLine("Watching camera/mic — Ctrl+C to stop.");
        new CameraMicMonitor().Watch(OnEvent, cts.Token);
        return 0;

        static void OnEvent(DeviceEvent e)
        {
            var device = e.Usage.Kind == DeviceKind.Webcam ? "webcam" : "mic";
            var verb = e.Kind == AvEventKind.Activated ? "ON " : "OFF";
            Console.WriteLine($"  [{verb}] {device} — {e.Usage.App}");
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
        Console.WriteLine("Watching DNS queries (ETW) — Ctrl+C to stop.");
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

    public static ToolReport Processes(bool flaggedOnly)
    {
        var procs = new ProcessLister(SharedVerifier).Snapshot();
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
                });
        }
        return b.Build($"{entries.Count} hosts entry(ies), {entries.Count(e => e.Notable)} flagged");
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
                $"{c.Store} — {c.Subject}",
                c.Notable ? string.Join("; ", c.Risks) : $"{c.SignatureAlgorithm}, {c.KeyBits}-bit",
                new Dictionary<string, string?>
                {
                    ["store"] = c.Store,
                    ["subject"] = c.Subject,
                    ["issuer"] = c.Issuer,
                    ["thumbprint"] = c.Thumbprint,
                    ["signatureAlgorithm"] = c.SignatureAlgorithm,
                    ["keyBits"] = c.KeyBits.ToString(),
                    ["hasPrivateKey"] = c.HasPrivateKey.ToString(),
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

    public static ToolReport Modules(bool flaggedOnly)
    {
        var modules = new ModuleLister(SharedVerifier).Snapshot();
        var flagged = modules.Where(m => m.Unsigned).ToList();
        var b = new ToolReport.Builder("modules");
        // The security signal is an unsigned/untrusted DLL loaded into a running
        // process (injection / search-order hijack). Listing every loaded module would
        // be pure noise, so items are the flagged modules; the summary carries totals.
        // (`--flagged` is implied here — the tool only ever reports notable modules.)
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
                b.Add(Severity.Info, $"{r.Direction}/{r.Action} — {r.DisplayName}", detail,
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
        // DNS-cache entries are visibility, not verdicts — all informational, so
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

    public static ToolReport Connections(bool flaggedOnly)
    {
        var connections = new ConnectionMonitor(SharedVerifier).Snapshot();

        // Opt-in VirusTotal enrichment for the owning binaries of noteworthy connections.
        var vt = VtLookups(connections.Where(c => c.Noteworthy && c.ImagePath is not null)
            .Select(c => c.ImagePath!));

        var b = new ToolReport.Builder("connections");
        foreach (var c in connections.Where(c => !flaggedOnly || c.Noteworthy)
                     .OrderByDescending(c => c.Noteworthy).ThenByDescending(c => c.External))
        {
            var report = c.ImagePath is not null && vt.TryGetValue(c.ImagePath, out var v) ? v : null;
            b.Add(
                c.Noteworthy ? Severity.Notable : Severity.Info,
                $"{c.Protocol} {c.Remote}",
                report is not null
                    ? $"{c.Process} (pid {c.Pid}) — {c.State}  [VT {report.Malicious}/{report.Total}]"
                    : $"{c.Process} (pid {c.Pid}) — {c.State}",
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
