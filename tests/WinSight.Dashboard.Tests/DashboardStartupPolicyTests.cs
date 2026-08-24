using Xunit;

namespace WinSight.Dashboard.Tests;

public sealed class DashboardStartupPolicyTests
{
    [Fact]
    public void OrdinaryDashboardStartsLongLivedMonitorsAndDoesNotAutoExit()
    {
        var policy = DashboardStartupPolicy.FromArguments([]);

        Assert.True(policy.StartMonitors);
        Assert.False(policy.ExitAfterIdle);
    }

    [Theory]
    [InlineData("--smoke-test")]
    [InlineData("--SMOKE-TEST")]
    public void SmokeDashboardExercisesUiWithoutStartingNativeMonitors(string argument)
    {
        var policy = DashboardStartupPolicy.FromArguments([argument]);

        Assert.False(policy.StartMonitors);
        Assert.True(policy.ExitAfterIdle);
    }
}
