using WinSight.NetMonitor;
using Xunit;

namespace WinSight.NetMonitor.Tests;

public sealed class NativeConnectionReaderTests
{
    [Theory]
    [InlineData(0xBB01u, 443)] // 0x01BB in network byte order
    [InlineData(0x5000u, 80)]  // 0x0050 in network byte order
    public void NetworkToHostPort_SwapsBytes(uint raw, int expected)
    {
        Assert.Equal(expected, NativeConnectionReader.NetworkToHostPort(raw));
    }

    [Fact]
    public void FormatEndpoint_RendersIpAndPort()
    {
        // 0x0100007F = 127.0.0.1 in network byte order; 0x5000 = port 80.
        Assert.Equal("127.0.0.1:80", NativeConnectionReader.FormatEndpoint(0x0100007Fu, 0x5000u));
    }

    [Theory]
    [InlineData(5u, "ESTABLISHED")]
    [InlineData(2u, "LISTENING")]
    [InlineData(99u, "UNKNOWN")]
    public void TcpStateName_MapsStates(uint state, string expected)
    {
        Assert.Equal(expected, NativeConnectionReader.TcpStateName(state));
    }
}

// Integration test — runs the real netstat snapshot + process resolution +
// signature batch on the Windows CI runner (validates the whole net pipeline).
public sealed class ConnectionMonitorIntegrationTests
{
    [Fact]
    public void Snapshot_ReturnsConnections_WithValidShape()
    {
        var connections = new ConnectionMonitor().Snapshot();
        Assert.NotNull(connections);
        Assert.All(connections, c =>
        {
            Assert.True(c.Protocol is "TCP" or "UDP");
            Assert.True(c.Pid >= 0);
            Assert.False(string.IsNullOrEmpty(c.Process));
        });
    }
}

public sealed class NetstatParserTests
{
    private const string Sample = """
        Active Connections

          Proto  Local Address          Foreign Address        State           PID
          TCP    127.0.0.1:5040         0.0.0.0:0              LISTENING       1234
          TCP    192.168.1.5:52345      140.82.121.4:443       ESTABLISHED     5678
          UDP    0.0.0.0:5353           *:*                                    900
        """;

    [Fact]
    public void Parse_ReadsTcpAndUdpRows()
    {
        var rows = NetstatParser.Parse(Sample);
        Assert.Equal(3, rows.Count);

        Assert.Equal("TCP", rows[1].Protocol);
        Assert.Equal("140.82.121.4:443", rows[1].Remote);
        Assert.Equal("ESTABLISHED", rows[1].State);
        Assert.Equal(5678, rows[1].Pid);

        Assert.Equal("UDP", rows[2].Protocol);
        Assert.Equal(string.Empty, rows[2].State);
        Assert.Equal(900, rows[2].Pid);
    }

    [Fact]
    public void Parse_IgnoresHeadersAndBlankLines()
    {
        Assert.Empty(NetstatParser.Parse("Active Connections\n\n  Proto  Local  Foreign  State  PID\n"));
    }

    [Theory]
    [InlineData("140.82.121.4:443", "140.82.121.4")]
    [InlineData("[fe80::1]:139", "fe80::1")]
    public void RemoteAddress_StripsPort(string endpoint, string expected)
    {
        Assert.Equal(expected, NetstatParser.RemoteAddress(endpoint));
    }

    [Theory]
    [InlineData("140.82.121.4", true)]   // public
    [InlineData("8.8.8.8", true)]        // public
    [InlineData("127.0.0.1", false)]     // loopback
    [InlineData("192.168.1.5", false)]   // private
    [InlineData("10.0.0.3", false)]      // private
    [InlineData("172.16.5.5", false)]    // private
    [InlineData("172.32.5.5", true)]     // outside 172.16-31 -> public
    [InlineData("0.0.0.0", false)]       // wildcard
    public void IsExternal_ClassifiesAddresses(string address, bool expected)
    {
        Assert.Equal(expected, NetstatParser.IsExternal(address));
    }
}
