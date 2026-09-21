using WinSight.Core;
using WinSight.Firewall;
using WinSight.Hosts;
using WinSight.NetMonitor;
using WinSight.Reporting;

namespace WinSight.Application;

public static partial class Adapters
{
    public static ToolReport Hosts(bool flaggedOnly)
    {
        var location = HostsReader.ResolveLocation();
        var snapshot = location.Path is null
            ? new HostsSnapshot([], Unreadable: true, Missing: false, MalformedLines: 0)
            : new HostsReader(location.Path).Read();
        var entries = snapshot.Entries;
        var b = new ToolReport.Builder("hosts");
        AddHostsLocationFindings(b, location);
        // Reported as a finding, not a footnote. The hosts file is world-readable on Windows, so a
        // refusal means its permissions were changed — which is precisely what someone who has just
        // pointed a bank or an update server at their own address would do next. Rendering that as
        // "0 entries, 0 flagged" would hand them a clean bill of health.
        if (snapshot.Unreadable && location.Path is not null)
        {
            b.Add(
                Severity.Notable,
                "hosts file could not be read",
                $"{location.Path} exists but access was denied; its contents are unknown",
                new Dictionary<string, string?>
                {
                    ["kind"] = "hostsUnreadable",
                    ["path"] = location.Path,
                    ["unreadable"] = bool.TrueString,
                });
        }
        if (snapshot.MalformedLines > 0)
        {
            b.Add(
                Severity.Notable,
                "hosts file contains malformed records",
                $"{snapshot.MalformedLines} active line(s) could not be interpreted as IP-to-host mappings",
                new Dictionary<string, string?>
                {
                    ["kind"] = "acquisitionCoverage",
                    ["malformedLines"] = snapshot.MalformedLines.ToString(System.Globalization.CultureInfo.InvariantCulture),
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
        var relocation = location.Relocated ? " (hosts database relocated)" : string.Empty;
        return b.Build((location.Path is null
            ? "hosts database relocated to a location that could not be resolved; its contents are unknown"
            : snapshot.Unreadable
            ? "hosts file exists but could not be read; its contents are unknown"
            : snapshot.MalformedLines > 0
            ? $"hosts file parsed incompletely: {snapshot.MalformedLines} malformed active line(s)"
            : $"{entries.Count} hosts entry(ies), {entries.Count(e => e.Notable)} flagged") + relocation);
    }

    /// <summary>
    /// Says where the hosts file was read from when that is not the standard place, and when the
    /// place could not be confirmed. Windows follows <c>Tcpip\Parameters\DataBasePath</c>; a scan
    /// that silently read the standard file instead would report someone else's clean copy.
    /// </summary>
    private static void AddHostsLocationFindings(ToolReport.Builder b, HostsLocation location)
    {
        if (location.Relocated)
        {
            b.Add(
                Severity.Notable,
                "hosts database relocated",
                location.Path is null
                    ? $@"Tcpip\Parameters\DataBasePath is ""{location.Registered}"", which is not a local path WinSight can resolve; Windows reads its hosts file from there, not from {HostsReader.DefaultPath()}"
                    : $@"Tcpip\Parameters\DataBasePath points Windows at {location.Path} instead of {HostsReader.DefaultPath()}; the entries below are read from there",
                new Dictionary<string, string?>
                {
                    ["kind"] = "hostsLocation",
                    ["registered"] = location.Registered,
                    ["path"] = location.Path,
                    ["standardPath"] = HostsReader.DefaultPath(),
                });
        }
        if (location.Unverified)
        {
            b.Add(
                Severity.Unverified,
                "hosts file location not confirmed",
                $@"Tcpip\Parameters could not be read, so the standard location {HostsReader.DefaultPath()} was assumed",
                new Dictionary<string, string?>
                {
                    ["kind"] = "hostsLocationUnverified",
                    ["path"] = location.Path,
                });
        }
    }

    public static ToolReport Firewall(bool flaggedOnly)
    {
        var acquisition = new FirewallRuleReader().ReadWithCoverage();
        var rules = acquisition.Items;
        var enabled = rules.Where(r => r.Enabled).ToList();
        var b = new ToolReport.Builder("firewall");
        // Read-only rule listing (informational); --flagged shows the summary only.
        if (!flaggedOnly)
        {
            foreach (var r in enabled.OrderBy(r => r.Direction).ThenBy(r => r.DisplayName, StringComparer.OrdinalIgnoreCase))
            {
                b.Add(Severity.Info, $"{r.Direction}/{r.Action}, {r.DisplayName}", FirewallRuleDetail(r),
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
        AddCoverageFinding(b, acquisition);
        return b.Build($"{rules.Count} rule(s), {enabled.Count} enabled{CoverageSuffix(acquisition)}");
    }

    /// <summary>
    /// What a firewall rule actually covers, in one line.
    /// </summary>
    /// <remarks>
    /// A rule that names neither a program nor a port applies to <b>everything</b>, and joining two
    /// empty strings rendered it as a blank line — so the broadest rules on the machine displayed the
    /// least information. Measured here: all 420 enabled rules produced an empty detail, because the
    /// reader supplies program and ports only for rules that scope themselves. Saying "any program,
    /// any port" is both the truth and the more interesting reading.
    /// </remarks>
    internal static string FirewallRuleDetail(FirewallRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var program = string.IsNullOrWhiteSpace(rule.Program) ? "any program" : rule.Program;
        var ports = string.IsNullOrWhiteSpace(rule.Ports) ? "any port" : rule.Ports;
        return $"{program}  {ports}";
    }

    public static ToolReport Dns(bool flaggedOnly)
    {
        var acquisition = new DnsCacheReader().ReadWithCoverage();
        var records = acquisition.Items;
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
        AddCoverageFinding(b, acquisition);
        return b.Build($"{records.Count} cached DNS record(s){CoverageSuffix(acquisition)}");
    }

    public static ToolReport Connections(
        bool flaggedOnly,
        bool allowNetworkLookups = true,
        CancellationToken cancellationToken = default)
    {
        var monitor = new ConnectionMonitor(SharedVerifier);
        var connections = monitor.Snapshot(cancellationToken);

        // Opt-in VirusTotal enrichment for the owning binaries of noteworthy connections. Ordered
        // most adverse first for the same reason as the persistence scan: the enricher looks up at
        // most four distinct files, in the order given. An unsigned binary holding a live connection
        // to an off-box address is the one worth spending a lookup on.
        var vt = VirusTotalEnricher.Lookup(
            connections.Where(c => c.Noteworthy && c.ImagePath is not null)
                .OrderByDescending(c => c.Signature.State is SignatureState.Unsigned
                    or SignatureState.SignedUntrusted)
                .ThenByDescending(c => c.External)
                .Select(c => c.ImagePath!),
            allowNetworkLookups,
            cancellationToken);

        var b = new ToolReport.Builder("connections");
        if (monitor.UsedNetstatFallback)
        {
            // Said out loud, like every other scanner says what it could not read. The fallback
            // re-derives the table by parsing a text rendering of it, which is a materially weaker
            // acquisition than the structured API - and the report used to present both as the same
            // answer.
            b.Add(
                Severity.Unverified,
                "connection table read indirectly",
                "the native connection API was unavailable, so this list was parsed from netstat "
                    + "output; process attribution is unchanged but the acquisition is weaker",
                new Dictionary<string, string?> { ["acquisition"] = "NetstatFallback" });
        }
        foreach (var c in connections.Where(c => !flaggedOnly || c.Noteworthy)
                     .OrderByDescending(c => c.Noteworthy).ThenByDescending(c => c.External))
        {
            var report = c.ImagePath is not null && vt.TryGetValue(c.ImagePath, out var v) ? v : null;
            var userRootTrust = c.ImagePath is not null && c.Signature.RestsOnUserInstalledTrust;
            var owner = WithUserRootNote($"{c.Process} (pid {c.Pid}), {c.State}", userRootTrust);
            b.Add(
                c.Noteworthy ? Severity.Notable : Severity.Info,
                $"{c.Protocol} {c.Remote}",
                report is not null
                    ? $"{owner}  [VT {report.Malicious}/{report.Total}]"
                    : owner,
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
                    ["signer"] = c.Signature.Signer,
                    ["userInstalledTrust"] = userRootTrust ? "true" : null,
                    ["microsoftSigned"] = c.ImagePath is null ? null : MicrosoftSignedField(c.Signature),
                    ["external"] = c.External.ToString(),
                    ["vtMalicious"] = report?.Malicious.ToString(),
                    ["vtTotal"] = report?.Total.ToString(),
                    ["vtLink"] = report?.Permalink,
                });
        }
        AddSignatureCoverageFinding(
            b,
            connections.Where(connection => connection.ImagePath is not null)
                .Select(connection => connection.Signature));
        return b.Build($"{connections.Count} connection(s), {connections.Count(c => c.Noteworthy)} noteworthy");
    }
}
