using Xunit;

namespace WinSight.Firewall.Tests;

/// <summary>
/// The rule and filter queries are bounded per result. They had no options at all, so each result
/// was awaited with an infinite timeout and a stuck firewall provider hung the scan and its Cancel.
/// </summary>
public sealed class WmiQueryOptionsTests
{
    [Fact]
    public void TheFirewallQueriesAreSemisynchronousForwardOnlyAndBounded()
    {
        var options = FirewallRuleReader.QueryOptions();

        Assert.True(options.ReturnImmediately);
        Assert.False(options.Rewindable);
        Assert.InRange(options.Timeout, TimeSpan.FromMilliseconds(1), TimeSpan.FromSeconds(30));
    }
}
