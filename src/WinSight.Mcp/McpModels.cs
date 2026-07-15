using System.Text.Json;
using System.Text.Json.Serialization;
using WinSight.Reporting;

namespace WinSight.Mcp;

public sealed record McpFinding(
    string Severity,
    string Title,
    string Detail,
    Dictionary<string, string> Fields);

public sealed record McpCapabilitiesResult(
    string SchemaVersion,
    string ProtocolVersion,
    bool ReadOnly,
    bool NetworkListener,
    bool NetworkReputationLookups,
    bool SensitiveEvidenceEnabled,
    List<McpScannerCapability> Scanners);

public sealed record McpScannerReport(
    string Tool,
    string Summary,
    int NotableCount,
    int TotalItemCount,
    int ReturnedItemCount,
    bool Truncated,
    List<McpFinding> Items);

public sealed record McpScanResult(
    string SchemaVersion,
    DateTimeOffset GeneratedAt,
    bool EvidenceIncluded,
    bool SensitiveFieldsIncluded,
    List<McpScannerReport> Reports);

internal static class McpJson
{
    internal static JsonSerializerOptions Options { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };
}

internal static class McpResultProjector
{
    private static readonly HashSet<string> SensitiveFieldNames = new(
        ["command", "commandLine"],
        StringComparer.OrdinalIgnoreCase);

    internal static McpScanResult Project(
        IReadOnlyList<ToolReport> reports,
        bool includeEvidence,
        bool includeSensitive,
        bool sensitiveEnabled,
        int maxItemsPerReport)
    {
        if (maxItemsPerReport is < 1 or > 200)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maxItemsPerReport),
                "maxItemsPerReport must be between 1 and 200.");
        }

        if (includeSensitive && !sensitiveEnabled)
        {
            throw new InvalidOperationException(
                "Sensitive evidence is disabled by the WinSight MCP server configuration.");
        }

        var projected = reports.Select(report =>
        {
            var selected = includeEvidence
                ? report.Items.Take(maxItemsPerReport).ToList()
                : [];
            var items = selected.Select(item => new McpFinding(
                item.Severity.ToString().ToLowerInvariant(),
                ProtectRequired(item.Title, includeSensitive),
                ProtectRequired(item.Detail, includeSensitive),
                includeSensitive
                    ? item.Fields
                        .Where(pair => pair.Value is not null)
                        .ToDictionary(pair => pair.Key, pair => pair.Value!, StringComparer.Ordinal)
                    : item.Fields
                        .Where(pair => !SensitiveFieldNames.Contains(pair.Key) && pair.Value is not null)
                        .ToDictionary(
                            pair => pair.Key,
                            pair => Protect(pair.Value, includeSensitive: false)!,
                            StringComparer.Ordinal)))
                .ToList();

            return new McpScannerReport(
                report.Tool,
                report.Summary,
                report.NotableCount,
                report.Items.Count,
                items.Count,
                includeEvidence && report.Items.Count > items.Count,
                items);
        }).ToList();

        return new McpScanResult(
            "1.0",
            DateTimeOffset.UtcNow,
            includeEvidence,
            includeEvidence && includeSensitive,
            projected);
    }

    // The user's folder paths are stable for the process lifetime, so the redaction table
    // is built and length-ordered once (longest key first, so nested paths win) instead of
    // being rebuilt for every field of every finding.
    private static readonly (string Path, string Token)[] PathRedactions =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)] = "%LOCALAPPDATA%",
            [Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)] = "%APPDATA%",
            [Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)] = "%USERPROFILE%",
            [Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar)] = "%TEMP%",
        }
        .Where(pair => !string.IsNullOrWhiteSpace(pair.Key))
        .OrderByDescending(pair => pair.Key.Length)
        .Select(pair => (pair.Key, pair.Value))
        .ToArray();

    private static string ProtectRequired(string value, bool includeSensitive) =>
        Protect((string?)value, includeSensitive) ?? string.Empty;

    private static string? Protect(string? value, bool includeSensitive)
    {
        if (value is null || includeSensitive)
        {
            return value;
        }

        var protectedValue = value;
        foreach (var (path, token) in PathRedactions)
        {
            protectedValue = protectedValue.Replace(path, token, StringComparison.OrdinalIgnoreCase);
        }
        return protectedValue;
    }
}
