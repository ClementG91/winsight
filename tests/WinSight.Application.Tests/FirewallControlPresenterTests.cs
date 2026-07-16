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

    // Allow and block apply to a stored policy and to an app still awaiting a decision.
    [Theory]
    [InlineData("policy")]
    [InlineData("pending")]
    public void ActionablePath_CoversEveryRowARulingApplies(string kind) =>
        Assert.Equal(
            @"C:\a.exe",
            FirewallControlPresenter.ActionablePath(Item(("kind", kind), ("path", @"C:\a.exe"))));

    [Fact]
    public void ActionablePath_IgnoresARowNoRulingApplies() =>
        Assert.Null(FirewallControlPresenter.ActionablePath(Item(("kind", "status"), ("path", @"C:\a.exe"))));

    // Removal is not the same question: there is nothing to remove for an app that has no policy
    // yet, and offering it would promise an action that does nothing.
    [Fact]
    public void PolicyPath_DoesNotCoverAnAppThatHasNoPolicyYet()
    {
        var pending = Item(("kind", "pending"), ("path", @"C:\a.exe"));

        Assert.Null(FirewallControlPresenter.PolicyPath(pending));
        Assert.NotNull(FirewallControlPresenter.ActionablePath(pending));
    }

    [Fact]
    public void IsPendingRow_RecognisesOnlyAPendingRow()
    {
        Assert.True(FirewallControlPresenter.IsPendingRow(Item(("kind", "pending"))));
        Assert.False(FirewallControlPresenter.IsPendingRow(Item(("kind", "policy"))));
        Assert.False(FirewallControlPresenter.IsPendingRow(Item(("kind", "status"))));
    }

    [Theory]
    [InlineData(FirewallMutationResult.Applied, "FirewallActionApplied")]
    [InlineData(FirewallMutationResult.ServiceUnavailable, "FirewallActionUnavailable")]
    [InlineData(FirewallMutationResult.Unauthorized, "FirewallActionUnauthorized")]
    [InlineData(FirewallMutationResult.NotSupported, "FirewallActionNotSupported")]
    [InlineData(FirewallMutationResult.Rejected, "FirewallActionRejected")]
    public void ResultMessageKey_MapsEveryOutcome(FirewallMutationResult result, string expected) =>
        Assert.Equal(expected, FirewallControlPresenter.ResultMessageKey(result));

    // Arming the machine is the moment saved blocks start cutting traffic, so it gets its own
    // message rather than the generic "change applied".
    [Fact]
    public void EnableEnforcementMessageKey_Applied_AnnouncesThatBlocksAreNowFiltering() =>
        Assert.Equal(
            "FirewallEnforcementEnabled",
            FirewallControlPresenter.EnableEnforcementMessageKey(FirewallMutationResult.Applied));

    // "This machine cannot filter" must never read as a generic rejection the user might retry.
    [Theory]
    [InlineData(FirewallMutationResult.NotSupported, "FirewallActionNotSupported")]
    [InlineData(FirewallMutationResult.Unauthorized, "FirewallActionUnauthorized")]
    [InlineData(FirewallMutationResult.ServiceUnavailable, "FirewallActionUnavailable")]
    [InlineData(FirewallMutationResult.Rejected, "FirewallActionRejected")]
    public void EnableEnforcementMessageKey_Failure_KeepsTheSpecificReason(
        FirewallMutationResult result, string expected) =>
        Assert.Equal(expected, FirewallControlPresenter.EnableEnforcementMessageKey(result));

    [Fact]
    public void OutcomeMessageKey_AppliedBlockWithoutEnforcement_SignalsNotEnforced() =>
        Assert.Equal(
            "FirewallActionAppliedNotEnforced",
            FirewallControlPresenter.OutcomeMessageKey(
                FirewallMutationResult.Applied, isBlock: true, enforcementEnabled: false));

    [Theory]
    [InlineData(true, true)]   // block, enforcing -> plain applied
    [InlineData(false, false)] // allow, not enforcing -> plain applied
    public void OutcomeMessageKey_OtherwiseMatchesResultMessage(bool isBlock, bool enforcing) =>
        Assert.Equal(
            "FirewallActionApplied",
            FirewallControlPresenter.OutcomeMessageKey(FirewallMutationResult.Applied, isBlock, enforcing));

    [Fact]
    public void OutcomeMessageKey_NonAppliedResult_UsesResultMessage() =>
        Assert.Equal(
            "FirewallActionUnavailable",
            FirewallControlPresenter.OutcomeMessageKey(
                FirewallMutationResult.ServiceUnavailable, isBlock: true, enforcementEnabled: false));
}
