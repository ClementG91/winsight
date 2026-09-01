using WinSight.Presence;

using Xunit;

namespace WinSight.Presence.Tests;

/// <summary>
/// The shipping event-log source, held to its own contract against the live machine.
/// </summary>
/// <remarks>
/// The scanner tests drive a scripted source, which proves the rules and proves nothing about the
/// only implementation that ships. That gap is exactly how a component ends up unable to report its
/// own blind spot — a scripted stub returning <c>unreadable: true</c> never exercises the code that
/// has to <i>set</i> it. These run the real reader.
/// </remarks>
public sealed class SystemLogWakeSourceTests
{
    private const string ResumeXml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <EventData>
            <Data Name="SleepTime">2026-08-28T20:15:00.0000000Z</Data>
            <Data Name="WakeSourceType">5</Data>
            <Data Name="WakeSourceText">USB Keyboard</Data>
          </EventData>
        </Event>
        """;

    /// <summary>
    /// <see cref="IWakeEventSource.Enumerate"/> promises never to throw. This holds the real reader
    /// to it, whatever state this machine's System log is in.
    /// </summary>
    [Fact]
    public void TheRealSourceEitherSeesWakesOrSaysItCouldNotLook()
    {
        var source = new SystemLogWakeSource();

        var wakes = source.Enumerate(PresenceScanner.DefaultMax).ToList();

        // A partially returned timeline must not also claim that the source was wholly unreadable.
        Assert.False(source.Unreadable && wakes.Count > 0);
        Assert.All(wakes, wake => Assert.NotEqual(default, wake.WokeUtc));
    }

    [Fact]
    public void ParseXml_ReadsTheLocaleIndependentResumePayload()
    {
        var woke = new DateTime(2026, 8, 28, 20, 20, 0, DateTimeKind.Utc);

        var record = SystemLogWakeSource.ParseXml(ResumeXml, woke);

        Assert.NotNull(record);
        Assert.Equal(new DateTimeOffset(woke), record.WokeUtc);
        Assert.Equal(
            DateTimeOffset.Parse("2026-08-28T20:15:00Z"),
            record.SleptUtc);
        Assert.Equal(WakeCause.PhysicalInput, record.Cause);
        Assert.Equal("USB Keyboard", record.Source);
        Assert.Equal(TimeSpan.FromMinutes(5), record.Asleep);
        Assert.True(record.IndicatesPresence);
    }

    [Fact]
    public void ParseXml_RejectsMalformedXmlAndMissingEventTime()
    {
        Assert.Null(SystemLogWakeSource.ParseXml("<Event>", DateTime.UtcNow));
        Assert.Null(SystemLogWakeSource.ParseXml(ResumeXml, timeCreated: null));
    }

    [Fact]
    public void ParseXml_TreatsUnknownOrInvalidFieldsConservatively()
    {
        const string xml = """
            <Event>
              <EventData>
                <Data Name="SleepTime">not-a-time</Data>
                <Data Name="WakeSourceType">not-a-number</Data>
                <Data Name="WakeSourceText">   </Data>
              </EventData>
            </Event>
            """;

        var record = SystemLogWakeSource.ParseXml(xml, DateTime.UtcNow);

        Assert.NotNull(record);
        Assert.Null(record.SleptUtc);
        Assert.Equal(WakeCause.Unknown, record.Cause);
        Assert.Null(record.Source);
        Assert.Null(record.Asleep);
        Assert.False(record.IndicatesPresence);
    }

    [Fact]
    public void EveryRecordReadFromTheLiveLogIsSelfConsistent()
    {
        var wakes = new SystemLogWakeSource().Enumerate(PresenceScanner.DefaultMax).ToList();

        Assert.All(wakes, wake =>
        {
            // A cause of PhysicalInput is an accusation that somebody was at the machine, so it may
            // only ever come from the classifier, never from an unmapped default.
            Assert.Equal(WakeSource.IndicatesPresence(wake.Cause), wake.IndicatesPresence);
            // A sleep duration is either unknown or positive; a negative one would render as
            // "woken after -3:00 asleep".
            Assert.True(wake.Asleep is null or { Ticks: > 0 });
        });
    }

    [Fact]
    public void AskingForNothingReadsNothingAndIsNotAnError()
    {
        var source = new SystemLogWakeSource();

        Assert.Empty(source.Enumerate(0));
        Assert.False(source.Unreadable);
    }

    [Fact]
    public void TheTimelineNeverExceedsTheRequestedMaximum()
    {
        var wakes = new SystemLogWakeSource().Enumerate(3).ToList();

        Assert.True(wakes.Count <= 3);
    }

    [Fact]
    public void TheScannerRunsEndToEndAgainstTheRealLog()
    {
        // The wiring, not the rules: a scanner whose default source was never constructed would
        // pass every scripted test and report nothing in production.
        var report = new PresenceScanner().Scan(max: 5);

        Assert.NotNull(report);
        Assert.True(report.Wakes.Count <= 5);
        Assert.Equal(report.Wakes.Count(wake => wake.IndicatesPresence), report.PresenceCount);
    }
}
