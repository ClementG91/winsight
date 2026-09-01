using System.Text.Json;

using WinSight.Reporting;
using Xunit;

namespace WinSight.Reporting.Tests;

/// <summary>
/// The versioned wrapper every <c>--json</c> emission carries.
/// </summary>
/// <remarks>
/// The contract has four independent readers - the MCP server, the VM qualification kit, the CFA
/// provider script, and whatever an operator schedules on top of it. A bare array gave none of them
/// a way to tell which version produced what they were reading, which is how adding
/// <c>unverifiedCount</c> became a silent break rather than a visible one.
/// </remarks>
public sealed class ReportEnvelopeTests
{
    private static ToolReport Sample()
    {
        var builder = new ToolReport.Builder("persistence");
        builder.Add(Severity.Notable, "RunKey/Evil", "unsigned", new Dictionary<string, string?>());
        return builder.Build("1 item(s), 1 flagged");
    }

    private static JsonElement Render(params ToolReport[] reports)
    {
        using var writer = new StringWriter();
        ReportRenderer.RenderJson(reports, writer);
        return JsonDocument.Parse(writer.ToString()).RootElement.Clone();
    }

    [Fact]
    public void TheRootIsAnObjectCarryingTheVersionTheTimeAndTheReports()
    {
        var root = Render(Sample());

        Assert.Equal(JsonValueKind.Object, root.ValueKind);
        Assert.Equal(
            ["schemaVersion", "generatedAt", "reports"],
            root.EnumerateObject().Select(property => property.Name));
    }

    [Fact]
    public void TheSchemaVersionIsTheOneThisBuildEmits() =>
        Assert.Equal(
            ReportEnvelope.CurrentSchemaVersion,
            Render(Sample()).GetProperty("schemaVersion").GetInt32());

    /// <summary>
    /// A stored report is evidence, and evidence that cannot say when it was true is worth less.
    /// UTC rather than local: an evidence folder is read somewhere else.
    /// </summary>
    [Fact]
    public void TheTimestampIsPresentAndInUtc()
    {
        var before = DateTimeOffset.UtcNow.AddSeconds(-5);

        var generatedAt = Render(Sample()).GetProperty("generatedAt").GetDateTimeOffset();

        Assert.Equal(TimeSpan.Zero, generatedAt.Offset);
        Assert.InRange(generatedAt, before, DateTimeOffset.UtcNow.AddSeconds(5));
    }

    [Fact]
    public void TheReportsKeepTheirOrderAndTheirShape()
    {
        var second = new ToolReport.Builder("hosts").Build("nothing");

        var reports = Render(Sample(), second).GetProperty("reports");

        Assert.Equal(2, reports.GetArrayLength());
        Assert.Equal("persistence", reports[0].GetProperty("tool").GetString());
        Assert.Equal("hosts", reports[1].GetProperty("tool").GetString());
        Assert.Equal(
            ["tool", "summary", "items", "notableCount", "unverifiedCount"],
            reports[0].EnumerateObject().Select(property => property.Name));
    }

    /// <summary>
    /// An empty scan still produces a well-formed document. Emitting nothing at all is
    /// indistinguishable from a crash, which is the failure this shape exists to avoid.
    /// </summary>
    [Fact]
    public void AnEmptyRunStillProducesAnEnvelope()
    {
        var root = Render();

        Assert.Equal(0, root.GetProperty("reports").GetArrayLength());
        Assert.Equal(
            ReportEnvelope.CurrentSchemaVersion, root.GetProperty("schemaVersion").GetInt32());
    }

    /// <summary>
    /// The version is a promise: bumping it is a decision, not something that happens because a
    /// property was added. This fails if the constant is edited without the thought.
    /// </summary>
    [Fact]
    public void TheCurrentSchemaVersionIsOne() =>
        Assert.Equal(1, ReportEnvelope.CurrentSchemaVersion);
}
