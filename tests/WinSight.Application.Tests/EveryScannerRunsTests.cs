using WinSight.Application;
using WinSight.Reporting;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// Every shipped scanner, executed for real against whatever machine is running the suite.
/// </summary>
/// <remarks>
/// <b>The gap this closes.</b> Every scanner's rules are tested through its own module with injected
/// seams, which is the right place for them — but until this, <i>not one scanner was ever executed
/// end to end by the test suite</i>. The only adapter that ran was <c>alerts</c>, which reads a file.
/// Everything else was proven correct in isolation and never proven to compose.
///
/// <b>Why that matters more than it sounds.</b> A scanner reads registry keys, WMI, event logs and
/// device classes that exist on the development machine and may simply not exist somewhere else:
/// Windows Home has no Group Policy keys, a server has no camera, a machine can have the Task
/// Scheduler service disabled, and Windows need not be on C:. Those absences are exactly where this
/// project keeps finding its defects — a component discarding what it cannot handle. A unit test
/// with a scripted source cannot see any of it.
///
/// <b>Why CI is the point.</b> These assertions are deliberately machine-agnostic: never a count,
/// never a specific finding, only that the scan completes and produces a coherent report. Run here
/// they prove little; run on a GitHub runner — a different Windows edition, a different locale, no
/// interactive session, none of this developer's software — they are the only evidence the suite has
/// that WinSight works on a machine nobody developed it on.
///
/// <b>Cost.</b> A full sweep is roughly two minutes, dominated by persistence and modules. That is
/// close to free in wall-clock terms: <c>build-test</c> runs beside the packaging job, which is
/// longer, so the workflow finishes no later than it did.
/// </remarks>
public sealed class EveryScannerRunsTests
{
    public static TheoryData<string> EveryScanner()
    {
        var data = new TheoryData<string>();
        foreach (var command in Adapters.SnapshotCommands.Order(StringComparer.Ordinal))
        {
            data.Add(command);
        }
        return data;
    }

    /// <summary>
    /// A scanner completes and describes itself, whatever this machine happens to have.
    /// </summary>
    /// <remarks>
    /// Network lookups are off: a scan must never depend on reaching the internet, and a CI runner
    /// has no VirusTotal key anyway. The assertions below are the contract every consumer relies on —
    /// the text renderer, the JSON contract, MCP and the dashboard all assume exactly this shape.
    /// </remarks>
    [Theory]
    [MemberData(nameof(EveryScanner))]
    public void AScannerCompletesAndProducesACoherentReport(string command)
    {
        var report = Adapters.Run(command, flaggedOnly: false, allowNetworkLookups: false);

        Assert.NotNull(report);
        Assert.False(string.IsNullOrWhiteSpace(report.Tool), "a report must name the tool that produced it");
        // The summary is the one line an operator always sees. An empty one reads as a scan that
        // found nothing, which is not the same as a scan that ran.
        Assert.False(string.IsNullOrWhiteSpace(report.Summary), $"{command} produced no summary");

        Assert.All(report.Items, item =>
        {
            Assert.False(string.IsNullOrWhiteSpace(item.Title), $"{command} produced an item with no title");
            Assert.False(string.IsNullOrWhiteSpace(item.Detail), $"{command} produced an item with no detail");
            Assert.NotNull(item.Fields);
            // A null or blank key would silently vanish from the JSON contract, taking its value
            // with it.
            Assert.All(item.Fields.Keys, key => Assert.False(string.IsNullOrWhiteSpace(key)));
        });

        Assert.Equal(report.Items.Count(item => item.Severity == Severity.Notable), report.NotableCount);
    }

    /// <summary>
    /// The flagged view is a subset of the full one, for every scanner.
    /// </summary>
    /// <remarks>
    /// <c>--flagged</c> is what an operator uses when they want the short list, and what automation
    /// keys its exit code on. A scanner that returned <i>more</i> under it, or that dropped a notable
    /// item, would be lying in the direction that matters.
    /// </remarks>
    [Theory]
    [MemberData(nameof(EveryScanner))]
    public void TheFlaggedViewNeverExceedsTheFullOne(string command)
    {
        var full = Adapters.Run(command, flaggedOnly: false, allowNetworkLookups: false);
        var flagged = Adapters.Run(command, flaggedOnly: true, allowNetworkLookups: false);

        Assert.True(
            flagged.Items.Count <= full.Items.Count,
            $"{command}: flagged returned {flagged.Items.Count} of {full.Items.Count}");
        Assert.True(
            flagged.NotableCount <= full.NotableCount,
            $"{command}: flagged reported more notable items than the full scan");
    }

    /// <summary>
    /// Every scanner survives the JSON contract, which is what MCP and automation consume.
    /// </summary>
    /// <remarks>
    /// A field carrying a control character or an unpaired surrogate — from a registry value, a
    /// certificate subject or a device name WinSight did not author — would break the document for
    /// every consumer at once, and only on the machine that happens to hold it.
    /// </remarks>
    [Theory]
    [MemberData(nameof(EveryScanner))]
    public void AScannersOutputSurvivesTheJsonContract(string command)
    {
        var report = Adapters.Run(command, flaggedOnly: false, allowNetworkLookups: false);

        using var writer = new StringWriter();
        ReportRenderer.RenderJson([report], writer);
        var json = writer.ToString();

        Assert.False(string.IsNullOrWhiteSpace(json));
        // Parsing it back is the assertion: a document that renders but will not read is no better
        // than one that never rendered.
        using var parsed = System.Text.Json.JsonDocument.Parse(json);
        Assert.NotEqual(System.Text.Json.JsonValueKind.Undefined, parsed.RootElement.ValueKind);
    }

    /// <summary>
    /// The default overview runs end to end.
    /// </summary>
    /// <remarks>
    /// This is what <c>winsight</c> with no arguments does, so it is the path most people take. It
    /// composes ten scanners behind one shared signature verifier; a fault in that sharing shows up
    /// here and nowhere else.
    ///
    /// The report name is deliberately not asserted to equal the command: several scanners are
    /// invoked as one word and report as another — <c>av</c> renders as <c>camera-mic</c>,
    /// <c>net</c> as <c>connections</c>, <c>certs</c> as <c>certificates</c> — because the command is
    /// what an operator types and the report name is what the domain is called. What must hold is
    /// that every scanner ran exactly once and named itself.
    /// </remarks>
    [Fact]
    public void TheDefaultOverviewRunsEveryToolItPromises()
    {
        var reports = Adapters.RunOverview(flaggedOnly: false, allowNetworkLookups: false);

        Assert.Equal(Adapters.OverviewCommands.Count, reports.Count);
        Assert.All(reports, report => Assert.False(string.IsNullOrWhiteSpace(report.Tool)));
        Assert.Equal(
            reports.Count,
            reports.Select(report => report.Tool).Distinct(StringComparer.Ordinal).Count());
    }
}
