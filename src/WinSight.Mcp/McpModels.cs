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
    // Declared for the same reason as the two flags above: an operator auditing this server should
    // be able to read every channel it opens out of the capability document. This one is true.
    bool FirewallServiceIpc,
    bool SensitiveEvidenceEnabled,
    List<McpScannerCapability> Scanners);

/// <param name="Offset">
/// The index of the first item returned. A caller reads the next page by asking again with
/// <c>offset = Offset + ReturnedItemCount</c>.
/// </param>
/// <param name="Truncated">
/// True when items after this page remain unread. It used to mean "there is more and you cannot
/// have it", which on a scan of 4538 autostart entries left 4338 of them unreachable: the model was
/// told evidence existed and given no way to ask for it. With an offset it means "ask again".
/// </param>
/// <param name="BudgetExhausted">
/// True when this page stopped short of <c>maxItems</c> because the response reached its size
/// budget. Reported separately from <paramref name="Truncated"/> because the remedy is different -
/// a smaller page, not a later one - and because a page that silently returned fewer items than
/// asked for is indistinguishable from a scan that found fewer.
/// </param>
public sealed record McpScannerReport(
    string Tool,
    string Summary,
    int NotableCount,
    int TotalItemCount,
    int ReturnedItemCount,
    int Offset,
    bool Truncated,
    bool BudgetExhausted,
    List<McpFinding> Items);

public sealed record McpScanResult(
    string SchemaVersion,
    DateTimeOffset GeneratedAt,
    bool EvidenceIncluded,
    bool SensitiveFieldsIncluded,
    List<McpScannerReport> Reports,
    // Carried on every result rather than only on the ones that happen to contain evidence: a
    // client that learns the rule once should not have to re-learn it per response, and a summary
    // still carries a machine-written tool name.
    string UntrustedDataNotice = UntrustedText.Notice);

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

    /// <summary>
    /// The characters of evidence one response may carry, across every report in it.
    /// </summary>
    /// <remarks>
    /// <b>Why an item count was not enough.</b> The cap was 200 items per report and nothing else.
    /// An item carries a title, a detail and up to fifteen fields, and those fields hold registry
    /// values, command lines and certificate subjects the machine's contents decide the length of -
    /// none of which this server authored. Two hundred items of ordinary evidence is a few tens of
    /// kilobytes; two hundred items whose fields happen to be long is megabytes, and a response
    /// large enough to fill the model's context is a denial of the tool by whoever wrote the
    /// registry value.
    ///
    /// The budget counts the characters actually emitted rather than serialising to measure, which
    /// would double the work to learn the size of what was just built. It is therefore an
    /// approximation of the wire size and deliberately conservative.
    /// </remarks>
    internal const int EvidenceCharacterBudget = 120_000;

    internal static McpScanResult Project(
        IReadOnlyList<ToolReport> reports,
        bool includeEvidence,
        bool includeSensitive,
        bool sensitiveEnabled,
        int maxItemsPerReport,
        int offset = 0)
    {
        if (maxItemsPerReport is < 1 or > 200)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maxItemsPerReport),
                "maxItemsPerReport must be between 1 and 200.");
        }
        ArgumentOutOfRangeException.ThrowIfNegative(offset);

        if (includeSensitive && !sensitiveEnabled)
        {
            throw new InvalidOperationException(
                "Sensitive evidence is disabled by the WinSight MCP server configuration.");
        }

        var remainingBudget = EvidenceCharacterBudget;
        var emittedAnyEvidence = false;
        var projected = reports.Select(report =>
        {
            var selected = includeEvidence
                ? report.Items.Skip(offset).Take(maxItemsPerReport).ToList()
                : [];
            // Title and Detail are prose positions - a client renders them into the conversation -
            // so they are delimited as well as neutralised. Field values sit in named JSON slots
            // that a client does not read as narrative, so they are neutralised only: wrapping
            // every one of fifteen fields per finding would triple the payload to restate a
            // boundary the structure already provides.
            var items = selected.Select(item => new McpFinding(
                item.Severity.ToString().ToLowerInvariant(),
                UntrustedText.Wrap(ProtectRequired(item.Title, includeSensitive)),
                UntrustedText.Wrap(ProtectRequired(item.Detail, includeSensitive)),
                includeSensitive
                    ? item.Fields
                        .Where(pair => pair.Value is not null)
                        .ToDictionary(
                            pair => pair.Key,
                            pair => UntrustedText.Neutralize(pair.Value!),
                            StringComparer.Ordinal)
                    : item.Fields
                        .Where(pair => !SensitiveFieldNames.Contains(pair.Key) && pair.Value is not null)
                        .ToDictionary(
                            pair => pair.Key,
                            pair => UntrustedText.Neutralize(Protect(pair.Value, includeSensitive: false)),
                            StringComparer.Ordinal)))
                .ToList();

            // Trimmed to the budget after projection rather than before, because the size of a
            // finding is only known once its fields have been neutralised and redacted.
            var budgetExhausted = false;
            var withinBudget = new List<McpFinding>(items.Count);
            foreach (var finding in items)
            {
                var cost = Size(finding);
                if (cost > remainingBudget)
                {
                    budgetExhausted = true;
                    if (emittedAnyEvidence)
                    {
                        break;
                    }
                    // A single first finding can be larger than the whole response budget. Return
                    // it once, mark the overrun, and let no later report force another exception.
                    withinBudget.Add(finding);
                    emittedAnyEvidence = true;
                    remainingBudget = 0;
                    break;
                }
                remainingBudget -= cost;
                withinBudget.Add(finding);
                emittedAnyEvidence = true;
            }

            return new McpScannerReport(
                report.Tool,
                UntrustedText.Neutralize(report.Summary),
                report.NotableCount,
                report.Items.Count,
                withinBudget.Count,
                includeEvidence ? offset : 0,
                includeEvidence && report.Items.Count > offset + withinBudget.Count,
                budgetExhausted,
                withinBudget);
        }).ToList();

        return new McpScanResult(
            "1.0",
            DateTimeOffset.UtcNow,
            includeEvidence,
            includeEvidence && includeSensitive,
            projected);
    }

    /// <summary>
    /// The characters one finding contributes: its prose positions and every field it carries.
    /// </summary>
    /// <remarks>
    /// Field names are counted as well as values. A finding with fifteen short values is not free -
    /// the keys, the quoting and the punctuation are most of it - and a budget that ignored them
    /// would be wrong in the direction that lets a response through.
    /// </remarks>
    private static int Size(McpFinding finding)
    {
        // A rough constant for the JSON structure around each finding and each field: braces,
        // quotes, colons and commas. Approximate on purpose; the point is not to under-count.
        const int PerFindingOverhead = 64;
        const int PerFieldOverhead = 8;

        var total = PerFindingOverhead
            + finding.Severity.Length + finding.Title.Length + finding.Detail.Length;
        foreach (var field in finding.Fields)
        {
            total += PerFieldOverhead + field.Key.Length + field.Value.Length;
        }
        return total;
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
