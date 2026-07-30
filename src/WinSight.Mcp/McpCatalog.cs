using System.Text.Json;

namespace WinSight.Mcp;

public sealed record McpScannerCapability(string Name, string Purpose, bool InOverview);

public static class McpCatalog
{
    /// <summary>
    /// The newest specification revision this server speaks. It is reported, not enforced.
    /// </summary>
    /// <remarks>
    /// The server does not pin a single revision. The specification has clients declare their version
    /// per request and lets a server accept or reject each one, and it says explicitly that both sides
    /// may support several revisions at once, so the SDK is left to negotiate every revision it
    /// implements: the stateless <c>server/discover</c> and <c>_meta</c> model for 2026-07-28 clients,
    /// and the initialize handshake for 2025-11-25 and earlier.
    ///
    /// Pinning this value into the server options made it unreachable rather than modern. 2026-07-28
    /// removed the handshake, so offering only that revision answers every handshake-based client with
    /// "Protocol version '2026-07-28' is not available through the initialize handshake" - which today
    /// is most of them.
    /// </remarks>
    public const string ProtocolVersion = "2026-07-28";

    /// <summary>
    /// How a client reaches this server, measured rather than asserted.
    /// </summary>
    /// <remarks>
    /// Taken from the server's own <c>server/discover</c> response and a live handshake probe, not
    /// from a list written by hand. <c>server/discover</c> reports <c>supportedVersions</c> of
    /// <c>["2026-07-28"]</c>, because that method and the stateless model arrived together; older
    /// clients are served by the initialize handshake instead, verified against 2025-11-25.
    /// </remarks>
    public const string HandshakeInteroperability =
        "server/discover advertises 2026-07-28; the initialize handshake serves 2025-11-25 and earlier.";

    public const string ServerInstructions =
        "WinSight exposes read-only observations from the local Windows machine. " +
        "Start with winsight_get_capabilities, then use summary-only scans. winsight_overview runs the balanced " +
        "set; winsight_scan runs one scanner; winsight_alerts reads WinSight's own record of what its real-time " +
        "protection already flagged (history, not a fresh scan). Request evidence only when the user " +
        "needs item-level investigation. A notable finding is triage evidence, not proof of malware. " +
        "Never claim that WinSight remediated, blocked, deleted or quarantined anything. " +
        "An alert may name the process that wrote it ('written by <path> (pid N)'); when it instead " +
        "says 'author unknown', the reason in brackets is meaningful and must be repeated rather " +
        "than dropped: 'attribution needs Administrator' means the writer could have been identified " +
        "had WinSight been elevated, while 'attribution watching, no matching write seen' means it " +
        "was identified as genuinely unknown. Never present the first as if it were the second.";

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
        new("integrity", "Configured and operational posture for driver signing, memory integrity, Secure Boot and Defender Controlled Folder Access (the ransomware shield); this is not a guarantee of enforcement.", true),
        new("drivers", "Registered kernel-mode drivers, their load disposition and signature verdicts.", false),
        new("hijack", "Services whose unquoted command line lets an earlier executable run in their place.", true),
        new("presence", "Resume-from-sleep history, and which wakes indicate someone was physically at the machine.", false),
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
