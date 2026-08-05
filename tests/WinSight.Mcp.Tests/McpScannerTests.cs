using System.Text.Json;
using WinSight.Application;
using Xunit;

namespace WinSight.Mcp.Tests;

/// <summary>
/// Pins the three places a scanner name appears to each other.
/// </summary>
/// <remarks>
/// The names used to live in a <c>[Description]</c> string that nothing compared against anything,
/// and it went stale: it advertised ten scanners while the dispatcher accepted fifteen, so
/// <c>input</c>, <c>integrity</c>, <c>drivers</c>, <c>hijack</c> and <c>presence</c> were reachable
/// and undiscoverable by any client reading the tool schema. Nothing failed, because nothing looked.
///
/// The equivalent guard already existed for <c>--help</c> on the CLI side
/// (<c>AdaptersTests.EverySnapshotCommand_IsDocumentedInHelp</c>), which is how that surface stopped
/// drifting. These are the same guard for the protocol surface.
/// </remarks>
public sealed class McpScannerTests
{
    [Fact]
    public void EveryProtocolScanner_IsACommandTheDispatcherRuns()
    {
        var unroutable = McpScanners.All
            .Select(McpScanners.Command)
            .Where(command => !Adapters.SnapshotCommands.Contains(command))
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            unroutable.Length == 0,
            $"winsight_scan offers scanners WinSight cannot run: {string.Join(", ", unroutable)}.");
    }

    [Fact]
    public void EveryScannerTheDispatcherRuns_IsOfferedByTheProtocol()
    {
        var offered = McpScanners.All.Select(McpScanners.Command).ToHashSet(StringComparer.Ordinal);
        var unreachable = Adapters.SnapshotCommands
            .Where(command => !offered.Contains(command))
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            unreachable.Length == 0,
            $"No MCP client can reach these scanners: {string.Join(", ", unreachable)}.");
    }

    /// <summary>The catalog a client reads and the enumeration constraining its call must agree.</summary>
    [Fact]
    public void TheCapabilityCatalogOffersExactlyTheProtocolScanners() =>
        Assert.Equal(
            McpScanners.All.Select(McpScanners.Command).Order(StringComparer.Ordinal),
            McpCatalog.Scanners.Select(scanner => scanner.Name).Order(StringComparer.Ordinal));

    /// <summary>
    /// The value the schema publishes is the value the parameter binds, verified by round-trip
    /// rather than assumed from a naming policy.
    /// </summary>
    /// <remarks>
    /// This is not theoretical. The first version relied on a camel-case policy handed to the
    /// converter's constructor, and the schema exporter did not read it: the published enumeration
    /// came out <c>"Persistence"</c> while <c>winsight_get_capabilities</c> answered
    /// <c>"persistence"</c>, so a client following the catalog would have sent a value its own
    /// schema rejected. Naming each member explicitly is what fixed it, and this asserts the fix
    /// rather than trusting it.
    /// </remarks>
    [Theory]
    [MemberData(nameof(AllScanners))]
    public void TheWireNameRoundTripsToTheCanonicalCommand(McpScanner scanner)
    {
        var command = McpScanners.Command(scanner);

        var serialized = JsonSerializer.Serialize(scanner);

        Assert.Equal($"\"{command}\"", serialized);
        Assert.Equal(scanner, JsonSerializer.Deserialize<McpScanner>(serialized));
    }

    /// <summary>An integer must not be accepted where a scanner name is expected.</summary>
    [Fact]
    public void AnOrdinalIsNotAScannerName() =>
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<McpScanner>("0"));

    public static TheoryData<McpScanner> AllScanners()
    {
        var data = new TheoryData<McpScanner>();
        foreach (var scanner in McpScanners.All)
        {
            data.Add(scanner);
        }
        return data;
    }
}
