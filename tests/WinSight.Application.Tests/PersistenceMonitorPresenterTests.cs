using WinSight.Application;
using WinSight.Attribution;
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

    /// <summary>
    /// A Run-key entry spelled the way the scanner spells it: the key, plus the registry view it
    /// was read through. The kernel reports only the key, so these tests are the proof that the two
    /// spellings still meet.
    /// </summary>
    private static AutostartEntry AtRunKey(string name, string target) =>
        new(AutostartVector.RunKey, name, $@"{RunKey} [64-bit]", target, target, target,
            ImageResolutionStatus.Present, SignatureVerdict.Unsigned);

    private const string RunKey = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

    [Fact]
    public void BuildReport_NamesTheProcessThatInstalledTheEntry()
    {
        // Driven through the real index, not a stand-in: the value of attribution is that a key
        // observed as "…\Run" answers a finding reported as "…\Run [64-bit]", and only the real
        // matching rule can show that.
        var index = new WriteAttributionIndex();
        index.Record(new WriteObservation(T0, 4242, @"C:\Users\me\Downloads\setup.exe", RunKey));

        var report = PersistenceMonitorPresenter.BuildReport(
            new[] { Event(AtRunKey("Updater", @"C:\evil.exe")) }, droppedChanges: 0, index.Attribute);

        var item = report.Items[0];
        Assert.Equal(@"C:\Users\me\Downloads\setup.exe", item.Fields["writtenBy"]);
        Assert.Equal("4242", item.Fields["writtenByPid"]);
        Assert.Contains("setup.exe", item.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildReport_WithoutAnAuthor_StillReportsTheDetection()
    {
        // The failure mode worth guarding: attribution is an enrichment, so a detection nobody can
        // explain must still be surfaced, unchanged, rather than quietly dropped.
        var index = new WriteAttributionIndex();

        var report = PersistenceMonitorPresenter.BuildReport(
            new[] { Event(AtRunKey("Updater", @"C:\evil.exe")) }, droppedChanges: 0, index.Attribute);

        var item = report.Items[0];
        Assert.Single(report.Items);
        Assert.Null(item.Fields["writtenBy"]);
        Assert.Null(item.Fields["writtenByPid"]);
        Assert.DoesNotContain("written by", item.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildReport_DoesNotBorrowAnAuthorFromAnotherKey()
    {
        // A wrong name beside a security finding is worse than no name.
        var index = new WriteAttributionIndex();
        index.Record(new WriteObservation(
            T0, 4242, @"C:\innocent.exe", @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Runtime"));

        var report = PersistenceMonitorPresenter.BuildReport(
            new[] { Event(AtRunKey("Updater", @"C:\evil.exe")) }, droppedChanges: 0, index.Attribute);

        Assert.Null(report.Items[0].Fields["writtenBy"]);
    }

    [Fact]
    public void BuildReport_AsksAboutTheMomentTheEntryWasFirstSeen()
    {
        // Guardian surfaces a detection whenever the operator opens the view, which can be long
        // after the arrival. Asking "who wrote this, now?" would lose the author to the retention
        // window; asking about first sight keeps it.
        var index = new WriteAttributionIndex();
        index.Record(new WriteObservation(T0, 7, @"C:\dropper.exe", RunKey));
        var seenLongAfter = new PersistenceEvent(
            PersistenceIdentity.FromEntry(AtRunKey("Updater", @"C:\evil.exe")),
            AtRunKey("Updater", @"C:\evil.exe"),
            T0,
            T0.AddHours(3),
            Observations: 4);

        var report = PersistenceMonitorPresenter.BuildReport(
            new[] { seenLongAfter }, droppedChanges: 0, index.Attribute);

        Assert.Equal(@"C:\dropper.exe", report.Items[0].Fields["writtenBy"]);
    }

    [Fact]
    public void AlertDetail_NamesTheProgramThatInstalledTheEntry()
    {
        var index = new WriteAttributionIndex();
        index.Record(new WriteObservation(T0, 4242, @"C:\Users\me\Downloads\setup.exe", RunKey));

        var detail = PersistenceMonitorPresenter.AlertDetail(
            Event(AtRunKey("Updater", @"C:\evil.exe")), index.Attribute);

        // The full path, not just the file name: the journal is read on one's own machine precisely
        // because one needs to know which program to go and look at.
        Assert.Contains(@"C:\Users\me\Downloads\setup.exe", detail, StringComparison.Ordinal);
        Assert.Contains("4242", detail, StringComparison.Ordinal);
        Assert.Contains(@"C:\evil.exe", detail, StringComparison.Ordinal);
    }

    [Fact]
    public void AlertDetail_WithoutAttribution_StillSaysWhatArrivedAndWhereItPoints()
    {
        // Unelevated is the normal case, so the alert must stay complete without an author.
        var detail = PersistenceMonitorPresenter.AlertDetail(Event(AtRunKey("Updater", @"C:\evil.exe")));

        Assert.Contains("Updater", detail, StringComparison.Ordinal);
        Assert.Contains(@"C:\evil.exe", detail, StringComparison.Ordinal);
        Assert.DoesNotContain("written by", detail, StringComparison.Ordinal);
    }

    [Fact]
    public void AlertDetail_SurvivesTheJournalLineFormat()
    {
        // The journal is one tab-separated line per alert, so a detail carrying a tab or newline
        // would make its own record unparseable — the alert would be written and then lost.
        var index = new WriteAttributionIndex();
        index.Record(new WriteObservation(T0, 4242, @"C:\setup.exe", RunKey));
        var detail = PersistenceMonitorPresenter.AlertDetail(
            Event(AtRunKey("Updater", @"C:\evil.exe")), index.Attribute);

        var alert = new SecurityAlert(T0, "Guardian", "RunKey", detail);
        var roundTripped = AlertJournal.Parse(AlertJournal.Format(alert));

        Assert.Equal(detail, roundTripped?.Detail);
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
