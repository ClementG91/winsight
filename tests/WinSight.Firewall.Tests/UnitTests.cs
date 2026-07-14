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

public sealed class OutboundPolicyEvaluatorTests
{
    [Fact]
    public void Evaluate_MatchesCanonicalPath_CaseInsensitively()
    {
        var path = Path.GetFullPath(@"C:\Program Files\WinSight\agent.exe");
        var evaluator = new OutboundPolicyEvaluator(
            [new AppFirewallPolicy(path.ToUpperInvariant(), OutboundAction.Block)]);

        Assert.Equal(OutboundAction.Block, evaluator.Evaluate(path.ToLowerInvariant()));
    }

    [Fact]
    public void Evaluate_UsesAskForUnknownProgram()
    {
        var evaluator = new OutboundPolicyEvaluator([]);

        Assert.Equal(OutboundAction.Ask, evaluator.Evaluate(@"C:\unknown.exe"));
    }

    [Fact]
    public void Constructor_IgnoresDisabledPolicy()
    {
        var evaluator = new OutboundPolicyEvaluator(
            [new AppFirewallPolicy(@"C:\disabled.exe", OutboundAction.Block, Enabled: false)]);

        Assert.Equal(OutboundAction.Ask, evaluator.Evaluate(@"C:\disabled.exe"));
    }

    [Fact]
    public void Constructor_RejectsAmbiguousDuplicatePolicy()
    {
        var policies = new[]
        {
            new AppFirewallPolicy(@"C:\same.exe", OutboundAction.Allow),
            new AppFirewallPolicy(@"c:\SAME.exe", OutboundAction.Block),
        };

        Assert.Throws<ArgumentException>(() => new OutboundPolicyEvaluator(policies));
    }

    [Theory]
    [InlineData("agent.exe")]
    [InlineData(".\\agent.exe")]
    public void Evaluate_RejectsRelativeExecutablePath(string path)
    {
        var evaluator = new OutboundPolicyEvaluator([]);

        Assert.Throws<ArgumentException>(() => evaluator.Evaluate(path));
    }

    [Fact]
    public void Evaluate_DoesNotExpandCallerEnvironmentVariables()
    {
        var evaluator = new OutboundPolicyEvaluator([]);

        Assert.Throws<ArgumentException>(() => evaluator.Evaluate(@"%SystemRoot%\System32\app.exe"));
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
