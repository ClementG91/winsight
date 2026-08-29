using WinSight.Application;
using WinSight.Persistence;
using WinSight.Reporting;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// The coverage gap has to survive a presentation layer that rewrites the summary line.
/// </summary>
/// <remarks>
/// <b>The regression.</b> Persistence was the one scanner of eleven reporting its coverage gap only
/// through <c>Summary</c>. The CLI and the MCP server print that string, so both showed it - and the
/// dashboard replaces <c>SummaryText</c> with its own "N results, M to examine" line, which dropped
/// it. The audience that lost the sentence is the non-technical one, on the scanner where the gap
/// was measured at 210 scheduled tasks an unelevated scan cannot open.
///
/// A finding lands in the results grid, which no presentation layer rewrites. These tests pin that
/// it appears exactly when coverage is partial, and that it stays out of the exit code.
/// </remarks>
public sealed class PersistenceCoverageFindingTests
{
    private static ToolReport Build(PersistenceCoverage coverage)
    {
        var builder = new ToolReport.Builder("persistence");
        Adapters.AddPersistenceCoverageFinding(builder, coverage);
        return builder.Build("summary");
    }

    [Fact]
    public void ACompleteScanAddsNothing() =>
        Assert.Empty(Build(PersistenceCoverage.Complete).Items);

    [Fact]
    public void APartialScanAddsAFindingNamingTheCountAndTheSurface()
    {
        var item = Assert.Single(Build(new PersistenceCoverage(210, ["Scheduled tasks"])).Items);

        Assert.Contains("210", item.Detail, StringComparison.Ordinal);
        Assert.Contains("Scheduled tasks", item.Detail, StringComparison.Ordinal);
        Assert.Equal("210", item.Fields["unreadableLocations"]);
        Assert.Equal("Scheduled tasks", item.Fields["unreadableSurfaces"]);
    }

    /// <summary>
    /// A surface that failed outright contributed no count, but the whole missing surface is the
    /// larger blind spot of the two and must still produce a finding.
    /// </summary>
    [Fact]
    public void ASurfaceThatFailedOutrightStillProducesAFinding()
    {
        var item = Assert.Single(Build(new PersistenceCoverage(0, ["Services"])).Items);

        Assert.Contains("Services", item.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("0 location", item.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// Not a finding about the machine. An unelevated scheduled task must not report failure for
    /// ever because it is unelevated - that is a scheduled task somebody turns off.
    /// </summary>
    [Fact]
    public void TheFindingDoesNotDriveTheExitCode()
    {
        var report = Build(new PersistenceCoverage(210, ["Scheduled tasks"]));

        Assert.Equal(Severity.Unverified, Assert.Single(report.Items).Severity);
        Assert.Equal(0, report.NotableCount);
        Assert.Equal(1, report.UnverifiedCount);
    }

    [Fact]
    public void ASurfaceIsNamedOnceEvenWhenItBothFailedAndSkipped()
    {
        var item = Assert.Single(
            Build(new PersistenceCoverage(3, ["Scheduled tasks", "Scheduled tasks"])).Items);

        var occurrences = item.Detail.Split("Scheduled tasks", StringSplitOptions.None).Length - 1;
        Assert.Equal(1, occurrences);
    }
}
