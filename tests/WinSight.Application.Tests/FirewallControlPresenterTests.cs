using WinSight.Application;
using WinSight.Firewall;
using WinSight.Reporting;
using Xunit;

namespace WinSight.Application.Tests;

public sealed class FirewallControlPresenterTests
{
    private static ReportItem Item(params (string Key, string Value)[] fields) =>
        new(Severity.Info, "svc", "detail",
            fields.ToDictionary(f => f.Key, f => (string?)f.Value));

    [Fact]
    public void IsPolicyRow_TrueForPolicyKind_FalseForStatus()
    {
        Assert.True(FirewallControlPresenter.IsPolicyRow(Item(("kind", "policy"), ("path", @"C:\a.exe"))));
        Assert.False(FirewallControlPresenter.IsPolicyRow(Item(("kind", "status"))));
        Assert.False(FirewallControlPresenter.IsPolicyRow(Item()));
    }

    [Fact]
    public void PolicyPath_ReturnsPathForPolicy_NullOtherwise()
    {
        Assert.Equal(@"C:\a.exe", FirewallControlPresenter.PolicyPath(Item(("kind", "policy"), ("path", @"C:\a.exe"))));
        Assert.Null(FirewallControlPresenter.PolicyPath(Item(("kind", "status"), ("path", @"C:\a.exe"))));
        Assert.Null(FirewallControlPresenter.PolicyPath(Item(("kind", "policy"))));
    }

    [Theory]
    [InlineData(FirewallMutationResult.Applied, "FirewallActionApplied")]
    [InlineData(FirewallMutationResult.ServiceUnavailable, "FirewallActionUnavailable")]
    [InlineData(FirewallMutationResult.Unauthorized, "FirewallActionUnauthorized")]
    [InlineData(FirewallMutationResult.Rejected, "FirewallActionRejected")]
    public void ResultMessageKey_MapsEveryOutcome(FirewallMutationResult result, string expected) =>
        Assert.Equal(expected, FirewallControlPresenter.ResultMessageKey(result));
}
