using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Server;
using WinSight.Application;

namespace WinSight.Mcp;

[McpServerToolType]
public sealed class WinSightMcpTools(McpScanService scans, McpSecurityOptions security)
{
    [McpServerTool(
        Name = "winsight_get_capabilities",
        Title = "Describe WinSight scanners",
        ReadOnly = true,
        Idempotent = true,
        Destructive = false,
        OpenWorld = false,
        UseStructuredContent = true)]
    [Description("Describe the local WinSight scanners and MCP privacy controls without scanning the machine.")]
    public McpCapabilitiesResult GetCapabilities() => new(
        "1.0",
        McpCatalog.ProtocolVersion,
        ReadOnly: true,
        NetworkListener: false,
        NetworkReputationLookups: false,
        security.AllowSensitiveEvidence,
        McpCatalog.Scanners.ToList());

    [McpServerTool(
        Name = "winsight_scan",
        Title = "Run one WinSight security check",
        ReadOnly = true,
        Idempotent = true,
        Destructive = false,
        OpenWorld = false,
        UseStructuredContent = true)]
    [Description(
        "Run one read-only local Windows security scanner. Network reputation lookups are always disabled. " +
        "Use summary-only output first; request evidence only when item-level investigation is needed.")]
    public async Task<McpScanResult> ScanAsync(
        [Description("Canonical scanner: persistence, av, net, dns, firewall, processes, modules, extensions, certs, or hosts.")]
        string scanner,
        [Description("Return only noteworthy findings. Keep true for normal AI triage.")]
        bool flaggedOnly = true,
        [Description("Include item-level evidence. False returns counts and summaries only.")]
        bool includeEvidence = false,
        [Description("Include raw command lines and user paths. Requires WINSIGHT_MCP_ALLOW_SENSITIVE=1 on the server.")]
        bool includeSensitive = false,
        [Description("Maximum evidence items returned, from 1 to 200.")]
        int maxItems = 50,
        CancellationToken cancellationToken = default)
    {
        if (!Adapters.SnapshotCommands.Contains(scanner))
        {
            throw new McpException("Unknown WinSight scanner. Call winsight_get_capabilities first.");
        }

        return await RunAndProjectAsync(
            scanner,
            flaggedOnly,
            includeEvidence,
            includeSensitive,
            maxItems,
            cancellationToken).ConfigureAwait(false);
    }

    [McpServerTool(
        Name = "winsight_overview",
        Title = "Run the balanced WinSight overview",
        ReadOnly = true,
        Idempotent = true,
        Destructive = false,
        OpenWorld = false,
        UseStructuredContent = true)]
    [Description(
        "Run WinSight's balanced read-only overview across persistence, camera/mic, network, DNS, " +
        "extensions, hosts and certificates. Large inventories remain opt-in through winsight_scan.")]
    public Task<McpScanResult> OverviewAsync(
        [Description("Return only noteworthy findings. Keep true for normal AI triage.")]
        bool flaggedOnly = true,
        [Description("Include item-level evidence. False returns counts and summaries only.")]
        bool includeEvidence = false,
        [Description("Include raw command lines and user paths. Requires WINSIGHT_MCP_ALLOW_SENSITIVE=1 on the server.")]
        bool includeSensitive = false,
        [Description("Maximum evidence items returned per scanner, from 1 to 200.")]
        int maxItemsPerScanner = 25,
        CancellationToken cancellationToken = default) =>
        RunAndProjectAsync(
            scanner: null,
            flaggedOnly,
            includeEvidence,
            includeSensitive,
            maxItemsPerScanner,
            cancellationToken);

    [McpServerTool(
        Name = "winsight_alerts",
        Title = "Read WinSight's real-time detection history",
        ReadOnly = true,
        Idempotent = true,
        Destructive = false,
        OpenWorld = false,
        UseStructuredContent = true)]
    [Description(
        "Read WinSight's own real-time detection journal: persistence changes and ransomware activity its " +
        "background protection flagged locally, including while the operator was away from the screen. This is " +
        "WinSight's recorded history, not a fresh scan of the machine, so it is a separate tool from the scanners. " +
        "Read-only; summary-only by default. An empty journal is normal on a machine that has flagged nothing.")]
    public Task<McpScanResult> AlertsAsync(
        [Description("Include each recorded detection. False returns counts only.")]
        bool includeEvidence = false,
        [Description("Include the full path in each detection's detail. Requires WINSIGHT_MCP_ALLOW_SENSITIVE=1 on the server.")]
        bool includeSensitive = false,
        [Description("Maximum recorded detections returned, from 1 to 200.")]
        int maxItems = 50,
        CancellationToken cancellationToken = default) =>
        // Goes through the same projector as the scanners, so the journal inherits the identical privacy
        // model — profile paths redacted unless the server was launched with sensitive evidence enabled.
        // "alerts" is dispatched by Adapters.Run but is deliberately absent from SnapshotCommands, which is
        // why it is its own tool rather than a winsight_scan target: it is history, not a machine snapshot.
        RunAndProjectAsync(
            scanner: "alerts",
            flaggedOnly: true,
            includeEvidence,
            includeSensitive,
            maxItems,
            cancellationToken);

    private async Task<McpScanResult> RunAndProjectAsync(
        string? scanner,
        bool flaggedOnly,
        bool includeEvidence,
        bool includeSensitive,
        int maxItems,
        CancellationToken cancellationToken)
    {
        if (maxItems is < 1 or > 200)
        {
            throw new McpException("Evidence limit must be between 1 and 200 items.");
        }
        if (includeSensitive && !includeEvidence)
        {
            throw new McpException("Sensitive fields require includeEvidence=true.");
        }
        if (includeSensitive && !security.AllowSensitiveEvidence)
        {
            throw new McpException(
                "Sensitive evidence is locked. The user must launch the server with WINSIGHT_MCP_ALLOW_SENSITIVE=1.");
        }

        try
        {
            var reports = await scans.RunAsync(scanner, flaggedOnly, cancellationToken).ConfigureAwait(false);
            return McpResultProjector.Project(
                reports,
                includeEvidence,
                includeSensitive,
                security.AllowSensitiveEvidence,
                maxItems);
        }
        catch (UnauthorizedAccessException)
        {
            throw new McpException("Windows denied access to this scanner. Run only that scan with appropriate privileges.");
        }
        catch (TimeoutException)
        {
            throw new McpException("The local WinSight scan exceeded the 90-second safety limit.");
        }
        catch (ArgumentOutOfRangeException)
        {
            throw new McpException("Invalid WinSight scanner or evidence limit.");
        }
    }
}
