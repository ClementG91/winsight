using WinSight.Presence;

using Xunit;

namespace WinSight.Presence.Tests;

/// <summary>
/// The resume timeline, driven by a scripted source so it is testable without an event log.
/// </summary>
public sealed class PresenceScannerTests
{
    private static readonly DateTimeOffset Night = new(2026, 7, 22, 3, 14, 0, TimeSpan.Zero);

    private sealed class ScriptedSource(IReadOnlyList<WakeRecord> wakes, bool unreadable = false)
        : IWakeEventSource
    {
        public bool Unreadable => unreadable;

        public int LastMax { get; private set; }

        public IEnumerable<WakeRecord> Enumerate(int max)
        {
            LastMax = max;
            return wakes.Take(max);
        }
    }

    private static WakeRecord Wake(DateTimeOffset at, WakeCause cause, string? source = null) =>
        new(at, at.AddHours(-4), cause, source);

    // ---- THE regression this check exists for -------------------------------------------------

    /// <summary>
    /// An unreadable log is reported as unreadable, never as a machine nobody visited.
    /// </summary>
    /// <remarks>
    /// The System log can be disabled, cleared or restricted. "No wakes recorded" and "I could not
    /// look" both produce an empty list, and only one of them is a fact about the machine — telling
    /// them apart is the difference between a check and a false reassurance.
    /// </remarks>
    [Fact]
    public void AnUnreadableLogIsNotReportedAsAQuietMachine()
    {
        var report = new PresenceScanner(new ScriptedSource([], unreadable: true)).Scan();

        Assert.Empty(report.Wakes);
        Assert.True(report.Unreadable);
    }

    [Fact]
    public void AMachineThatSimplyNeverSleptIsNotReportedAsUnreadable()
    {
        var report = new PresenceScanner(new ScriptedSource([])).Scan();

        Assert.Empty(report.Wakes);
        Assert.False(report.Unreadable);
    }

    // ---- What is counted as presence ----------------------------------------------------------

    [Fact]
    public void OnlyWakesAttributableToAHumanHandAreCountedAsPresence()
    {
        var report = new PresenceScanner(new ScriptedSource(
        [
            Wake(Night, WakeCause.PhysicalInput, "HID Keyboard Device"),
            Wake(Night.AddHours(1), WakeCause.Network, "Intel(R) Ethernet Connection"),
            Wake(Night.AddHours(2), WakeCause.Timer, "NT TASK"),
            Wake(Night.AddHours(3), WakeCause.Unknown),
        ])).Scan();

        Assert.Equal(4, report.Wakes.Count);
        Assert.Equal(1, report.PresenceCount);
    }

    [Fact]
    public void TheTimelineIsNewestFirst()
    {
        var report = new PresenceScanner(new ScriptedSource(
        [
            Wake(Night, WakeCause.Unknown),
            Wake(Night.AddHours(5), WakeCause.Unknown),
            Wake(Night.AddHours(2), WakeCause.Unknown),
        ])).Scan();

        Assert.Equal(
            [Night.AddHours(5), Night.AddHours(2), Night],
            report.Wakes.Select(wake => wake.WokeUtc));
    }

    [Fact]
    public void TheTimelineIsBoundedByTheRequestedMaximum()
    {
        var source = new ScriptedSource(
            Enumerable.Range(0, 200).Select(i => Wake(Night.AddHours(i), WakeCause.Unknown)).ToArray());

        var report = new PresenceScanner(source).Scan(max: 10);

        Assert.Equal(10, report.Wakes.Count);
        Assert.Equal(10, source.LastMax);
    }

    // ---- The record itself --------------------------------------------------------------------

    [Fact]
    public void ASleepDurationIsReportedOnlyWhenBothEndsAreKnown()
    {
        var known = new WakeRecord(Night, Night.AddHours(-8), WakeCause.Unknown, null);
        var openEnded = new WakeRecord(Night, null, WakeCause.Unknown, null);
        // A clock change or a malformed record can put the sleep after the wake; that is not a
        // negative duration, it is an unknown one.
        var inverted = new WakeRecord(Night, Night.AddHours(1), WakeCause.Unknown, null);

        Assert.Equal(TimeSpan.FromHours(8), known.Asleep);
        Assert.Null(openEnded.Asleep);
        Assert.Null(inverted.Asleep);
    }

    [Fact]
    public void ARecordKnowsWhetherItMeansSomebodyWasThere()
    {
        Assert.True(new WakeRecord(Night, null, WakeCause.PhysicalInput, "HID Keyboard").IndicatesPresence);
        Assert.False(new WakeRecord(Night, null, WakeCause.Network, "Ethernet").IndicatesPresence);
    }
}
