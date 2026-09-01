using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Server;
using WinSight.Application;
using WinSight.Reporting;

namespace WinSight.Mcp;

[McpServerToolType]
public sealed class WinSightMcpTools(
    McpScanService scans,
    McpSecurityOptions security,
    McpFirewallPostureService firewallPosture)
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
        "1.1",
        McpCatalog.ProtocolVersion,
        ReadOnly: true,
        NetworkListener: false,
        NetworkReputationLookups: false,
        FirewallServiceIpc: true,
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
        // The valid values are the schema's enumeration, not prose in this description. A
        // hand-written list here is what previously advertised ten of the fifteen scanners.
        [Description("Which scanner to run. winsight_get_capabilities describes what each one covers.")]
        McpScanner scanner,
        [Description("Return only noteworthy findings. Keep true for normal AI triage.")]
        bool flaggedOnly = true,
        [Description("Include item-level evidence. False returns counts and summaries only.")]
        bool includeEvidence = false,
        [Description("Include raw command lines and user paths. Requires WINSIGHT_MCP_ALLOW_SENSITIVE=1 on the server.")]
        bool includeSensitive = false,
        [Description("Maximum evidence items returned, from 1 to 200.")]
        int maxItems = 50,
        [Description(
            "Index of the first evidence item to return. Use with maxItems to read a large report "
            + "in pages: when a report comes back truncated, ask again with offset set to the "
            + "previous offset plus returnedItemCount.")]
        int offset = 0,
        CancellationToken cancellationToken = default)
    {
        var command = McpScanners.Command(scanner);

        // The schema already constrains the value, so this can only fire if a scanner were added to
        // the protocol enum without being wired into the dispatcher. Kept as a defence in depth in a
        // security tool: the alternative is an ArgumentOutOfRangeException surfacing as a generic
        // failure, and a test pins the two sets together so this should be unreachable.
        if (!Adapters.SnapshotCommands.Contains(command))
        {
            throw new McpException($"WinSight cannot run '{command}' on this build.");
        }

        return await RunAndProjectAsync(
            command,
            flaggedOnly,
            includeEvidence,
            includeSensitive,
            maxItems,
            offset,
            cancellationToken).ConfigureAwait(false);
    }

    [McpServerTool(
        Name = "winsight_process",
        Title = "Inspect one running process",
        ReadOnly = true,
        Idempotent = true,
        Destructive = false,
        OpenWorld = false,
        UseStructuredContent = true)]
    [Description(
        "Everything WinSight can say about one running process, gathered into a single view: its image and " +
        "signature, its parent, how many modules it has loaded and which of them are unsigned, and its live " +
        "external connections. Use this to follow up a process another scanner named, instead of re-running " +
        "and cross-referencing the processes, modules and connections scanners by hand. Read-only: it cannot " +
        "terminate, suspend or modify the process. A pid that is not running is reported as not running, " +
        "which is a different answer from a process that is running and has nothing notable.")]
    public async Task<McpScanResult> ProcessAsync(
        [Description("The process id to inspect.")]
        int pid,
        [Description("Include the unsigned modules and individual connections. False returns counts and the summary only.")]
        bool includeEvidence = false,
        [Description("Include raw command lines and user paths. Requires WINSIGHT_MCP_ALLOW_SENSITIVE=1 on the server.")]
        bool includeSensitive = false,
        [Description("Maximum evidence items returned, from 1 to 200.")]
        int maxItems = 50,
        [Description("Index of the first evidence item to return, for reading a large report in pages.")]
        int offset = 0,
        CancellationToken cancellationToken = default)
    {
        // Windows pids are positive; 0 is the System Idle Process, which has no image to inspect.
        // Rejecting it here keeps the tool from answering "not running" about something that is.
        if (pid <= 0)
        {
            throw new McpException("A process id must be greater than zero.");
        }

        ValidateDisclosure(includeEvidence, includeSensitive, maxItems, offset);

        // Routed through the same failure mapping as the scanners rather than left bare. The pivot
        // runs a process list, a module read and a connection sweep, so it can hit exactly the
        // access denials and timeouts a scan can, and a raw exception reaching the client turns a
        // known condition into an unexplained protocol failure.
        return await ProjectAsync(
            async () => [await scans.RunProcessAsync(pid, cancellationToken).ConfigureAwait(false)],
            includeEvidence,
            includeSensitive,
            maxItems,
            offset).ConfigureAwait(false);
    }

    [McpServerTool(
        Name = "winsight_overview",
        Title = "Run the balanced WinSight overview",
        ReadOnly = true,
        Idempotent = true,
        Destructive = false,
        OpenWorld = false,
        UseStructuredContent = true)]
    // Deliberately does not enumerate the set. The previous wording named seven scanners while the
    // overview ran ten, silently omitting keyboard-interception, code-integrity and hijack findings
    // from any summary a model wrote from this description. The catalog already marks which scanners
    // are in the overview and is pinned to the dispatcher by a test, so naming them again here would
    // reintroduce exactly the copy that drifted.
    [Description(
        "Run WinSight's balanced read-only overview. It covers the scanners winsight_get_capabilities " +
        "marks as in-overview; the large inventories stay opt-in through winsight_scan.")]
    public Task<McpScanResult> OverviewAsync(
        [Description("Return only noteworthy findings. Keep true for normal AI triage.")]
        bool flaggedOnly = true,
        [Description("Include item-level evidence. False returns counts and summaries only.")]
        bool includeEvidence = false,
        [Description("Include raw command lines and user paths. Requires WINSIGHT_MCP_ALLOW_SENSITIVE=1 on the server.")]
        bool includeSensitive = false,
        [Description("Maximum evidence items returned per scanner, from 1 to 200.")]
        int maxItemsPerScanner = 25,
        [Description("Index of the first evidence item to return per scanner, for reading in pages.")]
        int offset = 0,
        CancellationToken cancellationToken = default) =>
        RunAndProjectAsync(
            scanner: null,
            flaggedOnly,
            includeEvidence,
            includeSensitive,
            maxItemsPerScanner,
            offset,
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
        [Description("Index of the first recorded detection to return, for reading in pages.")]
        int offset = 0,
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
            offset,
            cancellationToken);

    [McpServerTool(
        Name = "winsight_outbound_firewall",
        Title = "Read WinSight's own outbound firewall posture",
        ReadOnly = true,
        Idempotent = true,
        Destructive = false,
        OpenWorld = false,
        UseStructuredContent = true)]
    [Description(
        "Read the posture of WinSight's own opt-in outbound firewall service: whether it is reachable, the mode " +
        "that was requested, the state actually running, applications seen reaching the network that nobody has " +
        "ruled on yet, and the stored per-application policies. This is a different subject from the 'firewall' " +
        "scanner, which inventories Microsoft Defender Firewall rules. Read-only: it cannot allow, block, arm or " +
        "disarm anything, and changing policy requires an elevated user in the WinSight dashboard. Requested mode " +
        "is intent, not proof of filtering, so describe traffic as blocked only when effectiveState is Active. " +
        "When available is False, WinSight could not verify the service; that is not a finding that outbound " +
        "filtering is off.")]
    public async Task<McpScanResult> OutboundFirewallAsync(
        [Description("Include each policy and pending application. False returns counts and the posture summary only.")]
        bool includeEvidence = false,
        [Description("Include unredacted executable paths. Requires WINSIGHT_MCP_ALLOW_SENSITIVE=1 on the server.")]
        bool includeSensitive = false,
        [Description("Maximum policies and pending applications returned, from 1 to 200.")]
        int maxItems = 50,
        CancellationToken cancellationToken = default)
    {
        ValidateDisclosure(includeEvidence, includeSensitive, maxItems);
        var report = await firewallPosture.ReadAsync(cancellationToken).ConfigureAwait(false);
        // Same projector as every other tool, so posture evidence inherits the identical privacy
        // model: executable paths under the user's profile are redacted unless the server was
        // launched with sensitive evidence enabled.
        return McpResultProjector.Project(
            [report],
            includeEvidence,
            includeSensitive,
            security.AllowSensitiveEvidence,
            maxItems);
    }

    private void ValidateDisclosure(
        bool includeEvidence, bool includeSensitive, int maxItems, int offset = 0)
    {
        if (maxItems is < 1 or > 200)
        {
            throw new McpException("Evidence limit must be between 1 and 200 items.");
        }
        if (offset < 0)
        {
            throw new McpException("The evidence offset cannot be negative.");
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
    }

    private async Task<McpScanResult> RunAndProjectAsync(
        string? scanner,
        bool flaggedOnly,
        bool includeEvidence,
        bool includeSensitive,
        int maxItems,
        int offset,
        CancellationToken cancellationToken)
    {
        ValidateDisclosure(includeEvidence, includeSensitive, maxItems, offset);

        return await ProjectAsync(
            () => scans.RunAsync(scanner, flaggedOnly, cancellationToken),
            includeEvidence,
            includeSensitive,
            maxItems,
            offset).ConfigureAwait(false);
    }

    /// <summary>
    /// Runs an acquisition and projects it, translating the conditions a local scan legitimately
    /// hits into protocol errors a client can act on.
    /// </summary>
    /// <remarks>
    /// Shared rather than repeated so a new tool cannot ship without the mapping, which is how
    /// <c>winsight_process</c> first shipped: it would have surfaced an access denial as an
    /// unexplained failure while every other tool explained the same condition.
    /// </remarks>
    private async Task<McpScanResult> ProjectAsync(
        Func<Task<IReadOnlyList<ToolReport>>> acquire,
        bool includeEvidence,
        bool includeSensitive,
        int maxItems,
        int offset = 0)
    {
        try
        {
            var reports = await acquire().ConfigureAwait(false);
            return McpResultProjector.Project(
                reports,
                includeEvidence,
                includeSensitive,
                security.AllowSensitiveEvidence,
                maxItems,
                offset);
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
