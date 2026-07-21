using System.Text.Json;

namespace WinSight.Mcp;

public sealed record McpScannerCapability(string Name, string Purpose, bool InOverview);

public static class McpCatalog
{
    public const string ProtocolVersion = "2025-11-25";

    public const string ServerInstructions =
        "WinSight exposes read-only observations from the local Windows machine. " +
        "Start with winsight_get_capabilities, then use summary-only scans. winsight_overview runs the balanced " +
        "set; winsight_scan runs one scanner; winsight_alerts reads WinSight's own record of what its real-time " +
        "protection already flagged (history, not a fresh scan). Request evidence only when the user " +
        "needs item-level investigation. A notable finding is triage evidence, not proof of malware. " +
        "Never claim that WinSight remediated, blocked, deleted or quarantined anything.";

    public static IReadOnlyList<McpScannerCapability> Scanners { get; } =
    [
        new("persistence", "Autostart and persistence surfaces with signature verdicts.", true),
        new("av", "Current and historical camera or microphone use.", true),
        new("net", "Active TCP/UDP connections with process attribution.", true),
        new("dns", "Records currently visible in the Windows DNS cache.", true),
        new("firewall", "Enabled Microsoft Defender Firewall rule inventory.", false),
        new("processes", "Running processes, image identities and signature verdicts.", false),
        new("modules", "Unsigned or untrusted modules loaded into accessible processes.", false),
        new("extensions", "Browser extensions and broad permission signals.", true),
        new("certs", "Trusted root certificates and risky trust-store properties.", true),
        new("hosts", "Hosts-file redirects and security-service blocking signals.", true),
        new("input", "Kernel drivers positioned to see every keystroke or mouse movement.", true),
        new("drivers", "Registered kernel-mode drivers, their load disposition and signature verdicts.", false),
    ];

    public static string CapabilitiesJson(bool sensitiveEnabled) => JsonSerializer.Serialize(new
    {
        schemaVersion = "1.0",
        protocolVersion = ProtocolVersion,
        transport = "stdio",
        networkListener = false,
        readOnly = true,
        mutationTools = false,
        networkReputationLookups = false,
        sensitiveEvidenceEnabled = sensitiveEnabled,
        scanners = Scanners,
    }, McpJson.Options);

    public const string SecurityModel = """
        # WinSight MCP security model

        - Local `stdio` child process only; no HTTP endpoint or listening socket.
        - Every exposed tool is read-only, idempotent and closed-world.
        - VirusTotal and all other network enrichment are disabled in the MCP process.
        - Summary-only results are the default. Item evidence must be requested explicitly.
        - User-profile paths are redacted and command/command-line fields are omitted by default.
        - Raw sensitive fields require both `includeSensitive=true` and the server-side
          `WINSIGHT_MCP_ALLOW_SENSITIVE=1` launch setting.
        - Results are bounded and may be marked truncated. One scan runs at a time.
        - Notable findings are triage evidence, not a malware verdict.
        - No process, file, registry, firewall, service or WFP mutation is exposed.
        """;
}
