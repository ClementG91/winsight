using WinSight.Firewall;
using Xunit;

namespace WinSight.Firewall.Tests;

public sealed class PendingOutboundLogTests
{
    private static readonly DateTimeOffset T0 = new(2026, 7, 16, 12, 0, 0, TimeSpan.Zero);

    // The caller notifies on a true, so an app that connects a thousand times must produce exactly
    // one notification, not a thousand.
    [Fact]
    public void Observe_IsTrueOnlyTheFirstTimeAnAppIsSeen()
    {
        var log = new PendingOutboundLog();

        Assert.True(log.Observe(@"C:\apps\a.exe", "1.2.3.4:443", T0));
        Assert.False(log.Observe(@"C:\apps\a.exe", "5.6.7.8:443", T0.AddSeconds(1)));
        Assert.False(log.Observe(@"C:\apps\a.exe", "9.9.9.9:80", T0.AddSeconds(2)));

        var app = Assert.Single(log.Snapshot());
        Assert.Equal(3, app.Observations);
    }

    // An app's identity is its canonical path; the same binary reached by a different spelling is
    // the same app, or an operator's single decision would not cover it.
    [Theory]
    [InlineData(@"C:\apps\a.exe", @"c:\APPS\A.EXE")]
    [InlineData(@"C:\apps\a.exe", @"C:\apps\.\a.exe")]
    [InlineData(@"C:\apps\a.exe", @"C:\apps\sub\..\a.exe")]
    [InlineData(@"C:\apps\a.exe", "\"C:\\apps\\a.exe\"")]
    public void Observe_TreatsTheSameBinaryAsOneApp(string first, string second)
    {
        var log = new PendingOutboundLog();

        Assert.True(log.Observe(first, "1.2.3.4:443", T0));
        Assert.False(log.Observe(second, "1.2.3.4:443", T0));

        Assert.Single(log.Snapshot());
    }

    [Fact]
    public void Observe_KeepsFirstSeen_AndAdvancesLastSeenAndRemote()
    {
        var log = new PendingOutboundLog();

        log.Observe(@"C:\apps\a.exe", "1.2.3.4:443", T0);
        log.Observe(@"C:\apps\a.exe", "5.6.7.8:80", T0.AddMinutes(5));

        var app = Assert.Single(log.Snapshot());
        Assert.Equal(T0, app.FirstSeenUtc);
        Assert.Equal(T0.AddMinutes(5), app.LastSeenUtc);
        Assert.Equal("5.6.7.8:80", app.LastRemote);
    }

    // Observations arrive from an ETW callback on every connect, so an unbounded log is a
    // memory-growth primitive any process could drive.
    [Fact]
    public void Observe_IsBounded()
    {
        var log = new PendingOutboundLog();

        for (var i = 0; i < PendingOutboundLog.MaxPendingApps + 50; i++)
        {
            log.Observe($@"C:\apps\a{i}.exe", "1.2.3.4:443", T0);
        }

        Assert.Equal(PendingOutboundLog.MaxPendingApps, log.Snapshot().Count);
    }

    // Evicting to make room would let a flood of noise push the one interesting app out of the
    // list, which is exactly what an attacker would want. Refuse the new instead.
    [Fact]
    public void Observe_WhenFull_KeepsTheAppsAlreadyRecorded()
    {
        var log = new PendingOutboundLog();
        log.Observe(@"C:\apps\first.exe", "1.2.3.4:443", T0);
        for (var i = 0; i < PendingOutboundLog.MaxPendingApps + 50; i++)
        {
            log.Observe($@"C:\flood\f{i}.exe", "1.2.3.4:443", T0.AddSeconds(1));
        }

        Assert.Contains(log.Snapshot(), app =>
            app.ExecutablePath.Equals(@"C:\apps\first.exe", StringComparison.OrdinalIgnoreCase));
    }

    // A tool that hides its own blind spot is worse than one without the feature: the caller must
    // be able to say "and more were not recorded" rather than show a truncated list as complete.
    [Fact]
    public void Observe_WhenFull_CountsWhatItRefused_RatherThanDroppingSilently()
    {
        var log = new PendingOutboundLog();
        for (var i = 0; i < PendingOutboundLog.MaxPendingApps; i++)
        {
            log.Observe($@"C:\apps\a{i}.exe", "1.2.3.4:443", T0);
        }
        Assert.Equal(0, log.DroppedApps);

        log.Observe(@"C:\apps\overflow1.exe", "1.2.3.4:443", T0);
        log.Observe(@"C:\apps\overflow2.exe", "1.2.3.4:443", T0);

        Assert.Equal(2, log.DroppedApps);
    }

    // A full log must still count new connections from apps it already knows.
    [Fact]
    public void Observe_WhenFull_StillTracksKnownApps()
    {
        var log = new PendingOutboundLog();
        for (var i = 0; i < PendingOutboundLog.MaxPendingApps; i++)
        {
            log.Observe($@"C:\apps\a{i}.exe", "1.2.3.4:443", T0);
        }

        Assert.False(log.Observe(@"C:\apps\a0.exe", "9.9.9.9:443", T0.AddSeconds(1)));

        var app = Assert.Single(log.Snapshot(), item =>
            item.ExecutablePath.Equals(@"C:\apps\a0.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(2, app.Observations);
        Assert.Equal("9.9.9.9:443", app.LastRemote);
        Assert.Equal(0, log.DroppedApps);
    }

    [Fact]
    public void Resolve_ForgetsTheApp_AndReportsWhetherThereWasAnything()
    {
        var log = new PendingOutboundLog();
        log.Observe(@"C:\apps\a.exe", "1.2.3.4:443", T0);

        Assert.True(log.Resolve(@"c:\APPS\A.EXE"));
        Assert.Empty(log.Snapshot());
        Assert.False(log.Resolve(@"C:\apps\a.exe"));
    }

    // A resolved app that connects again is genuinely new information: the operator's decision was
    // recorded, so the caller filters it. If it reaches here, it is worth surfacing again.
    [Fact]
    public void Observe_AfterResolve_IsReportedAsNewAgain()
    {
        var log = new PendingOutboundLog();
        log.Observe(@"C:\apps\a.exe", "1.2.3.4:443", T0);
        log.Resolve(@"C:\apps\a.exe");

        Assert.True(log.Observe(@"C:\apps\a.exe", "1.2.3.4:443", T0.AddMinutes(1)));
    }

    // The newest arrival is what an operator reads first.
    [Fact]
    public void Snapshot_OrdersMostRecentlySeenFirst()
    {
        var log = new PendingOutboundLog();
        log.Observe(@"C:\apps\old.exe", "1.2.3.4:443", T0);
        log.Observe(@"C:\apps\new.exe", "1.2.3.4:443", T0.AddMinutes(1));

        Assert.Equal(
            [@"C:\apps\new.exe", @"C:\apps\old.exe"],
            log.Snapshot().Select(app => app.ExecutablePath));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("relative.exe")]
    public void Observe_RejectsAnIdentityNoPolicyCouldBeKeyedOn(string path)
    {
        var log = new PendingOutboundLog();

        Assert.ThrowsAny<ArgumentException>(() => log.Observe(path, "1.2.3.4:443", T0));
    }

    // Observations come off an ETW trace thread while the pipe reads the snapshot.
    [Fact]
    public async Task Observe_AndSnapshot_AreSafeFromSeveralThreads()
    {
        var log = new PendingOutboundLog();

        await Task.WhenAll(Enumerable.Range(0, 8).Select(worker => Task.Run(() =>
        {
            for (var i = 0; i < 200; i++)
            {
                log.Observe($@"C:\apps\a{i % 40}.exe", $"1.2.3.4:{i}", T0.AddSeconds(i));
                log.Snapshot();
            }
        })));

        Assert.Equal(40, log.Snapshot().Count);
        Assert.Equal(8 * 200, log.Snapshot().Sum(app => app.Observations));
    }
}
