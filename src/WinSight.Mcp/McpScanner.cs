using System.Text.Json;
using System.Text.Json.Serialization;
using WinSight.Application;

namespace WinSight.Mcp;

/// <summary>
/// The scanners <c>winsight_scan</c> will run, as a closed set the protocol itself carries.
/// </summary>
/// <remarks>
/// <b>This is a type rather than a string because the string drifted.</b> The parameter used to be
/// a free <c>string</c> whose valid values lived only in its <c>[Description]</c>, and that
/// description listed ten scanners while the dispatcher accepted fifteen: <c>input</c>,
/// <c>integrity</c>, <c>drivers</c>, <c>hijack</c> and <c>presence</c> were reachable and
/// undiscoverable. A client reading the tool schema — which is how a model decides what it can ask
/// for — had no way to learn that a whole privilege-escalation scanner existed.
///
/// The same failure had already happened once on the CLI side, where a <c>hijack</c> scanner
/// shipped wired into everything except <c>--help</c>. The fix there was to stop maintaining a
/// second copy and derive it; this is that fix for the protocol surface. The valid values now
/// travel in the JSON Schema as an enumeration, so they cannot be stale relative to the parameter
/// they constrain, and <c>McpCatalogTests</c> pins this set against
/// <see cref="Adapters.SnapshotCommands"/> so a new scanner cannot reach the dispatcher without
/// reaching the protocol.
/// </remarks>
/// <remarks>
/// Every member spells its wire name explicitly with <see cref="JsonStringEnumMemberNameAttribute"/>
/// rather than relying on a naming policy. That is not decoration: the schema the SDK publishes is
/// produced by the schema exporter, and a policy passed to a converter's constructor was measured
/// <b>not</b> to reach it — the published enumeration came out <c>"Persistence"</c> while
/// <c>winsight_get_capabilities</c> answered <c>"persistence"</c>, so a client following the catalog
/// would have violated the schema constraining the same parameter. Naming each value once, on the
/// member, is the only form both the exporter and the converter read.
/// </remarks>
[JsonConverter(typeof(McpScannerJsonConverter))]
public enum McpScanner
{
    [JsonStringEnumMemberName("persistence")] Persistence,
    [JsonStringEnumMemberName("av")] Av,
    [JsonStringEnumMemberName("net")] Net,
    [JsonStringEnumMemberName("dns")] Dns,
    [JsonStringEnumMemberName("firewall")] Firewall,
    [JsonStringEnumMemberName("processes")] Processes,
    [JsonStringEnumMemberName("modules")] Modules,
    [JsonStringEnumMemberName("extensions")] Extensions,
    [JsonStringEnumMemberName("certs")] Certs,
    [JsonStringEnumMemberName("hosts")] Hosts,
    [JsonStringEnumMemberName("input")] Input,
    [JsonStringEnumMemberName("integrity")] Integrity,
    [JsonStringEnumMemberName("drivers")] Drivers,
    [JsonStringEnumMemberName("hijack")] Hijack,
    [JsonStringEnumMemberName("presence")] Presence,
}

/// <summary>
/// Serializes <see cref="McpScanner"/> as the lower-case command name the rest of WinSight uses,
/// so the value a client sends over the protocol is the value the dispatcher already understands.
/// </summary>
internal sealed class McpScannerJsonConverter : JsonStringEnumConverter<McpScanner>
{
    public McpScannerJsonConverter()
        : base(namingPolicy: null, allowIntegerValues: false)
    {
    }
}

/// <summary>Translation between the protocol enum and WinSight's canonical command names.</summary>
public static class McpScanners
{
    /// <summary>
    /// The canonical command name for a scanner. Every member is a single word, so the camel-case
    /// policy the converter applies and this lower-casing produce the same string — which
    /// <c>McpCatalogTests</c> asserts by round-tripping rather than by assuming.
    /// </summary>
    public static string Command(McpScanner scanner) =>
        scanner.ToString().ToLowerInvariant();

    /// <summary>Every scanner this server offers, in declaration order.</summary>
    public static IReadOnlyList<McpScanner> All { get; } = Enum.GetValues<McpScanner>();
}
