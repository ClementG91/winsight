using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSight.Reporting;

/// <summary>
/// Renders tool reports as human text or as the stable JSON contract. One renderer
/// for every tool, so output stays consistent as the suite grows and automation/GUIs
/// have a single shape to parse.
/// </summary>
public static class ReportRenderer
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        // camelCase property names — the idiomatic JSON contract. Dictionary keys in
        // Fields are already camelCase and pass through unchanged.
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public static void RenderText(ToolReport report, TextWriter writer)
    {
        writer.WriteLine($"== {report.Tool} == {report.Summary}");
        foreach (var item in report.Items)
        {
            var mark = item.Severity == Severity.Notable ? "[!]" : "[ ]";
            writer.WriteLine($"  {mark} {item.Title}");
            if (item.Detail.Length > 0)
            {
                writer.WriteLine($"        {item.Detail}");
            }
        }
    }

    public static void RenderJson(IReadOnlyList<ToolReport> reports, TextWriter writer) =>
        writer.WriteLine(JsonSerializer.Serialize(reports, JsonOptions));
}
