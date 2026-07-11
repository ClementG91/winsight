using Xunit;

namespace WinSight.Hosts.Tests;

public sealed class HostsReaderTests
{
    private static readonly string[] Sample =
    {
        "# Copyright header",
        "127.0.0.1       localhost",
        "0.0.0.0 ads.tracker.example      # benign adblock sink",
        "127.0.0.1   www.mcafee.com",           // AV blackhole
        "203.0.113.66  login.mybank.example",   // external hijack
        "   ",                                    // blank
        "203.0.113.66 a.example b.example",       // one IP, two names
    };

    [Fact]
    public void Parse_SkipsCommentsAndBlanks_ExpandsMultiNameLines()
    {
        var entries = HostsReader.Parse(Sample);

        Assert.Equal(6, entries.Count); // localhost, ads, mcafee, mybank, a, b
        Assert.Contains(entries, e => e is { IpAddress: "203.0.113.66", Hostname: "a.example" });
        Assert.Contains(entries, e => e is { IpAddress: "203.0.113.66", Hostname: "b.example" });
    }

    [Fact]
    public void BenignAdblockSink_IsNotFlagged()
    {
        var e = new HostEntry("0.0.0.0", "ads.tracker.example");
        Assert.False(e.Notable);
    }

    [Fact]
    public void SinkingSecurityDomain_IsFlagged()
    {
        var e = new HostEntry("127.0.0.1", "www.mcafee.com");
        Assert.True(e.Notable);
        Assert.Contains("AV/Update", e.Reason);
    }

    [Fact]
    public void ExternalRedirect_IsFlagged()
    {
        var e = new HostEntry("203.0.113.66", "login.mybank.example");
        Assert.True(e.Notable);
        Assert.Contains("hijack", e.Reason);
    }

    [Fact]
    public void PlainLocalhost_IsNotFlagged()
    {
        var e = new HostEntry("127.0.0.1", "localhost");
        Assert.False(e.Notable);
    }

    [Fact]
    public void Snapshot_OnRealHostsFile_DoesNotThrow()
    {
        var entries = new HostsReader().Snapshot();
        Assert.NotNull(entries);
    }
}
