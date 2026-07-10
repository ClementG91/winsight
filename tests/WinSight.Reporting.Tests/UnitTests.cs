using WinSight.Reporting;
using Xunit;

namespace WinSight.Reporting.Tests;

public sealed class ReportRendererTests
{
    private static ToolReport SampleReport() => new ToolReport.Builder("persistence")
        .Add(Severity.Notable, "RunKey/Evil", @"C:\evil.exe",
            new Dictionary<string, string?> { ["signature"] = "Unsigned", ["signer"] = null })
        .Add(Severity.Info, "Service/OK", @"C:\ok.exe",
            new Dictionary<string, string?> { ["signature"] = "SignedTrusted" })
        .Build("2 item(s), 1 flagged");

    [Fact]
    public void NotableCount_CountsOnlyNotable()
    {
        Assert.Equal(1, SampleReport().NotableCount);
    }

    [Fact]
    public void RenderText_MarksNotableItems()
    {
        var sw = new StringWriter();
        ReportRenderer.RenderText(SampleReport(), sw);
        var text = sw.ToString();
        Assert.Contains("== persistence == 2 item(s), 1 flagged", text);
        Assert.Contains("[!] RunKey/Evil", text);
        Assert.Contains("[ ] Service/OK", text);
    }

    [Fact]
    public void RenderJson_EmitsCamelCaseEnum_AndOmitsNulls()
    {
        var sw = new StringWriter();
        ReportRenderer.RenderJson(new[] { SampleReport() }, sw);
        var json = sw.ToString();
        Assert.Contains("\"tool\": \"persistence\"", json);
        Assert.Contains("\"severity\": \"notable\"", json); // enum -> camelCase string
        Assert.Contains("\"signature\": \"Unsigned\"", json);
        Assert.Contains("\"signer\": null", json); // nulls are explicit in the contract
    }
}
