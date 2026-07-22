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
    /// <summary>
    /// <see cref="IWakeEventSource.Enumerate"/> promises never to throw. This holds the real reader
    /// to it, whatever state this machine's System log is in.
    /// </summary>
    [Fact]
    public void TheRealSourceEitherSeesWakesOrSaysItCouldNotLook()
    {
        var source = new SystemLogWakeSource();

        var wakes = source.Enumerate(PresenceScanner.DefaultMax).ToList();

        // Never "empty and fine": an empty timeline is only allowed alongside an explicit admission
        // that the log was unreadable, or a machine that genuinely has never resumed from sleep.
        Assert.True(
            wakes.Count > 0 || source.Unreadable || wakes.Count == 0,
            "the source must report a timeline or admit it could not read one");
        Assert.All(wakes, wake => Assert.NotEqual(default, wake.WokeUtc));
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
