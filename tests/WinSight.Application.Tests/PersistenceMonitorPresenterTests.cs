using WinSight.Application;
using WinSight.Core;
using WinSight.Persistence;
using WinSight.Reporting;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class PersistenceMonitorPresenterTests
{
    private static readonly DateTimeOffset T0 = new(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);

    private static PersistenceEvent Event(AutostartEntry entry, int observations = 1) =>
        new(PersistenceIdentity.FromEntry(entry), entry, T0, T0, observations);

    private static AutostartEntry Unsigned(string name, string target) =>
        new(AutostartVector.RunKey, name, $"loc:{name}", target, target, target,
            ImageResolutionStatus.Present, SignatureVerdict.Unsigned);

    private static AutostartEntry Signed(string name, string target) =>
        new(AutostartVector.RunKey, name, $"loc:{name}", target, target, target,
            ImageResolutionStatus.Present, new SignatureVerdict(SignatureState.SignedTrusted, "Contoso"));

    [Fact]
    public void BuildReport_MapsSeverityAndTagsLiveKind()
    {
        var report = PersistenceMonitorPresenter.BuildReport(
            new[] { Event(Unsigned("Evil", @"C:\evil.exe")), Event(Signed("Ok", @"C:\ok.exe")) },
            droppedChanges: 0);

        Assert.Equal("persistence-live", report.Tool);
        Assert.Equal(2, report.Items.Count);

        var evil = report.Items[0];
        Assert.Equal(Severity.Notable, evil.Severity);
        Assert.Equal(PersistenceMonitorPresenter.LiveKind, evil.Fields["kind"]);
        Assert.Equal(@"C:\evil.exe", evil.Fields["path"]);
        Assert.Equal("RunKey", evil.Fields["vector"]);

        Assert.Equal(Severity.Info, report.Items[1].Severity);
    }

    [Fact]
    public void BuildReport_Summary_NamesTheBlindSpotWhenLogDropped()
    {
        var withDrop = PersistenceMonitorPresenter.BuildReport(
            new[] { Event(Unsigned("A", @"C:\a.exe")) }, droppedChanges: 3);
        var noDrop = PersistenceMonitorPresenter.BuildReport(
            new[] { Event(Unsigned("A", @"C:\a.exe")) }, droppedChanges: 0);

        Assert.Contains("not recorded", withDrop.Summary, StringComparison.Ordinal);
        Assert.DoesNotContain("not recorded", noDrop.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildReport_Empty_IsAValidEmptyReport()
    {
        var report = PersistenceMonitorPresenter.BuildReport(Array.Empty<PersistenceEvent>(), 0);

        Assert.Empty(report.Items);
        Assert.Equal(0, report.NotableCount);
    }

    [Theory]
    [InlineData(true, "GuardianDetectedNotable")]
    [InlineData(false, "GuardianDetectedSigned")]
    public void BalloonMessageKey_LoudForNotable_CalmForSigned(bool unsigned, string expectedKey)
    {
        var ev = unsigned ? Event(Unsigned("X", @"C:\x.exe")) : Event(Signed("X", @"C:\x.exe"));

        Assert.Equal(expectedKey, PersistenceMonitorPresenter.BalloonMessageKey(ev));
    }

    [Fact]
    public void GuardianHost_CreateDefault_BuildsAMonitorWithoutScanning()
    {
        // Construction must not touch the machine; only Start() seeds via a real scan.
        using var monitor = GuardianHost.CreateDefault();

        Assert.NotNull(monitor);
        Assert.False(monitor.Core.IsSeeded);
    }
}
