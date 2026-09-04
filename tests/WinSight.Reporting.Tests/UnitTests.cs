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
    public void RenderText_NeutralizesTerminalAndVisualControlCharacters()
    {
        var report = new ToolReport.Builder("tool\u001b[2J")
            .Add(
                Severity.Notable,
                "Run/Evil\r\n[ ] forged",
                "path\u202Eexe\u200B",
                new Dictionary<string, string?>())
            .Build("summary\nforged");
        var sw = new StringWriter();

        ReportRenderer.RenderText(report, sw);

        var text = sw.ToString();
        Assert.DoesNotContain('\u001b', text);
        Assert.DoesNotContain('\u202e', text);
        Assert.DoesNotContain('\u200b', text);
        Assert.DoesNotContain("Run/Evil\r\n", text, StringComparison.Ordinal);
        Assert.Contains(@"tool\u001B[2J", text, StringComparison.Ordinal);
        Assert.Contains(@"Run/Evil\r\n[ ] forged", text, StringComparison.Ordinal);
        Assert.Contains(@"path\u202Eexe\u200B", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Neutralize_BoundsUntrustedDisplayText()
    {
        var neutralized = UntrustedDisplayText.Neutralize(new string('x', 100), maxLength: 32);

        Assert.Equal(32, neutralized.Length);
        Assert.EndsWith("…[truncated]", neutralized, StringComparison.Ordinal);
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

    [Fact]
    public void RenderJson_PreservesControlCharactersAsEvidence()
    {
        const string title = "Run\u001b[2J\r\n\u202Eexe";
        var report = new ToolReport.Builder("test")
            .Add(Severity.Notable, title, "detail", new Dictionary<string, string?>())
            .Build("done");
        var sw = new StringWriter();

        ReportRenderer.RenderJson([report], sw);

        using var document = System.Text.Json.JsonDocument.Parse(sw.ToString());
        var renderedTitle = document.RootElement.GetProperty("reports")[0]
            .GetProperty("items")[0]
            .GetProperty("title")
            .GetString();
        Assert.Equal(title, renderedTitle);
    }
}
