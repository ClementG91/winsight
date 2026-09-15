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

    [Fact]
    public void TheExplorerVerbOpensOnlyTheSignatureWindowForItsPath()
    {
        var policy = DashboardStartupPolicy.FromArguments(["--signature", @"C:\Users\me\Downloads\setup.exe"]);

        Assert.True(policy.SignatureMode);
        Assert.Equal(@"C:\Users\me\Downloads\setup.exe", policy.SignaturePath);
        // A right-click must not start a second dashboard's monitors and tray icon.
        Assert.False(policy.StartMonitors);
        Assert.False(policy.ExitAfterIdle);
    }

    [Fact]
    public void ASignatureRequestWithoutAPathStaysInSignatureMode()
    {
        var policy = DashboardStartupPolicy.FromArguments(["--SIGNATURE"]);

        Assert.True(policy.SignatureMode);
        Assert.Null(policy.SignaturePath);
        Assert.False(policy.StartMonitors);
    }

    [Fact]
    public void AnOrdinaryStartIsNotSignatureMode() =>
        Assert.False(DashboardStartupPolicy.FromArguments(["--language", "fr"]).SignatureMode);
}
