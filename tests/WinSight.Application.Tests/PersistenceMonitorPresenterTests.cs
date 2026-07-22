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
        // ...and it says *why* there is no author. A silent absence reads as "attribution was
        // watching and had nothing to report", which is the opposite of what unelevated means.
        Assert.Contains("author unknown (attribution not running)", detail, StringComparison.Ordinal);
    }

    [Fact]
    public void AlertDetail_DistinguishesUnelevatedFromWatchingAndSeeingNothing()
    {
        var refused = new AttributionHealth(
            Running: false, Attributed: 0, UnknownProcess: 0, UnannouncedKey: 0,
            UntranslatablePath: 0, Refused: true);
        var watching = refused with { Running = true, Refused = false };

        var unelevated = PersistenceMonitorPresenter.AlertDetail(
            Event(AtRunKey("Updater", @"C:\evil.exe")), attribute: null, health: refused);
        var blind = PersistenceMonitorPresenter.AlertDetail(
            Event(AtRunKey("Updater", @"C:\evil.exe")), attribute: null, health: watching);

        // "Run it as Administrator and you will get a name" and "the answer really is unknown" are
        // different instructions to the person reading this line.
        Assert.Contains("needs Administrator", unelevated, StringComparison.Ordinal);
        Assert.Contains("no matching write seen", blind, StringComparison.Ordinal);
        Assert.NotEqual(unelevated, blind);
    }

    public static TheoryData<ImageResolutionStatus, SignatureState, string> Verdicts => new()
    {
        { ImageResolutionStatus.Present, SignatureState.Unsigned, "unsigned" },
        { ImageResolutionStatus.Present, SignatureState.SignedUntrusted, "invalid signature" },
        { ImageResolutionStatus.Present, SignatureState.SignedTrusted, "signature valid" },
        { ImageResolutionStatus.FileMissing, SignatureState.Missing, "file missing" },
    };

    [Theory]
    [MemberData(nameof(Verdicts))]
    public void AlertDetail_SaysWhetherTheArrivalIsSigned(
        ImageResolutionStatus imageStatus, SignatureState signature, string expected)
    {
        // The one thing the removed persistence-live report showed that the journal did not. An
        // operator reading an alert hours later needs the verdict in the same line — "a new startup
        // item appeared" and "an unsigned new startup item appeared" are different emergencies.
        var entry = new AutostartEntry(
            AutostartVector.RunKey, "Updater", $@"{RunKey} [64-bit]", @"C:\evil.exe", @"C:\evil.exe",
            @"C:\evil.exe", imageStatus, new SignatureVerdict(signature, null));

        var detail = PersistenceMonitorPresenter.AlertDetail(Event(entry));

        Assert.Contains(expected, detail, StringComparison.Ordinal);
    }

    [Fact]
    public void AlertDetail_DoesNotDressABareNameUpAsALocatedFile()
    {
        // A bare-name launch is exactly the living-off-the-land case, so naming it matters — but
        // "powershell.exe" and "C:\Windows\...\powershell.exe" mean different things to someone
        // deciding what to do next, and the alert must not blur them.
        var index = new WriteAttributionIndex();
        index.Record(new WriteObservation(T0, 4242, "powershell.exe", RunKey, PathIsExact: false));

        var detail = PersistenceMonitorPresenter.AlertDetail(
            Event(AtRunKey("Updater", @"C:\evil.exe")), index.Attribute);

        Assert.Contains("powershell.exe", detail, StringComparison.Ordinal);
        Assert.Contains("full path unknown", detail, StringComparison.Ordinal);
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
