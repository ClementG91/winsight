using WinSight.Application;
using WinSight.Core;
using WinSight.Persistence;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// The one line an operator reads after a persistence scan. It has to distinguish "there is nothing
/// there" from "I was not allowed to look".
/// </summary>
public sealed class PersistenceSummaryTests
{
    private static readonly AutostartEntry Clean = new(
        AutostartVector.RunKey, "Thing", "loc", @"C:\thing.exe", @"C:\thing.exe", @"C:\thing.exe",
        ImageResolutionStatus.Present, new SignatureVerdict(SignatureState.SignedTrusted, "Contoso"));

    [Fact]
    public void ACompleteScanSaysNothingAboutCoverage()
    {
        var summary = Adapters.PersistenceSummary([Clean], PersistenceCoverage.Complete);

        Assert.Equal("1 autostart item(s), 0 flagged", summary);
    }

    // The measured case: 210 scheduled tasks under \Windows\System32\Tasks that an unelevated scan
    // cannot open, one of which was already flagged. Silence here reads as a clean surface.
    [Fact]
    public void APartialScanNamesTheCountAndTheSurface()
    {
        var summary = Adapters.PersistenceSummary(
            [Clean], new PersistenceCoverage(210, ["Scheduled tasks"]));

        Assert.Contains("210 not readable without elevation", summary, StringComparison.Ordinal);
        Assert.Contains("Scheduled tasks", summary, StringComparison.Ordinal);
    }

    // A surface that failed outright has no count — it contributed nothing — but must still be
    // named, because a whole missing surface is the larger blind spot of the two.
    [Fact]
    public void ASurfaceThatFailedOutrightIsStillNamed()
    {
        var summary = Adapters.PersistenceSummary(
            [Clean], new PersistenceCoverage(0, ["Services"]));

        Assert.Contains("not readable without elevation", summary, StringComparison.Ordinal);
        Assert.Contains("Services", summary, StringComparison.Ordinal);
    }

    [Fact]
    public void ASurfaceIsNamedOnceEvenWhenItBothFailedAndSkipped()
    {
        var summary = Adapters.PersistenceSummary(
            [Clean], new PersistenceCoverage(3, ["Scheduled tasks", "Scheduled tasks"]));

        var occurrences = summary.Split("Scheduled tasks", StringSplitOptions.None).Length - 1;
        Assert.Equal(1, occurrences);
    }
}
