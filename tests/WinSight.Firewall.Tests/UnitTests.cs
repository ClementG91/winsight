using WinSight.Firewall;
using Xunit;

namespace WinSight.Firewall.Tests;

public sealed class FirewallEnumTests
{
    [Theory]
    [InlineData(1, FirewallDirection.Inbound)]
    [InlineData(2, FirewallDirection.Outbound)]
    [InlineData(9, FirewallDirection.Unknown)]
    public void Direction_Maps(int value, FirewallDirection expected)
    {
        Assert.Equal(expected, FirewallEnum.Direction(value));
    }

    [Theory]
    [InlineData(2, FirewallAction.Allow)]
    [InlineData(4, FirewallAction.Block)]
    [InlineData(0, FirewallAction.Unknown)]
    public void Action_Maps(int value, FirewallAction expected)
    {
        Assert.Equal(expected, FirewallEnum.Action(value));
    }
}

// Integration test — reads the real Windows Firewall rules on the CI runner.
public sealed class FirewallRuleReaderIntegrationTests
{
    [Fact]
    public void Read_DoesNotThrow_AndRulesAreSane()
    {
        var rules = new FirewallRuleReader().Read();
        Assert.NotNull(rules);
        // A stock Windows install ships many firewall rules.
        Assert.NotEmpty(rules);
        Assert.All(rules, r => Assert.False(string.IsNullOrEmpty(r.DisplayName)));
    }
}
