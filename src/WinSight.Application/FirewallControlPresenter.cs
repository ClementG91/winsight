using WinSight.Firewall;
using WinSight.Reporting;

namespace WinSight.Application;

/// <summary>
/// UI-agnostic helpers for the dashboard's interactive firewall controls: it reads a
/// policy row out of a report item and maps a mutation outcome to a localization key. This
/// keeps the decision logic out of the WPF layer so it is unit-tested without a UI, and it
/// is the single place that knows the report field names the adapter writes.
/// </summary>
public static class FirewallControlPresenter
{
    /// <summary>True when the report item describes a per-application policy (not the status line).</summary>
    public static bool IsPolicyRow(ReportItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return Field(item, "kind") == "policy";
    }

    /// <summary>True when the row is an app seen reaching the network that nobody has ruled on.</summary>
    public static bool IsPendingRow(ReportItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return Field(item, "kind") == "pending";
    }

    /// <summary>The executable path of a policy row, or null when the item is not a policy.</summary>
    public static string? PolicyPath(ReportItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return IsPolicyRow(item) ? PathOf(item) : null;
    }

    /// <summary>
    /// The executable an allow or block would apply to: a stored policy, or an app still awaiting a
    /// decision. Distinct from <see cref="PolicyPath"/>, which gates removal — there is nothing to
    /// remove for an app that has no policy yet, so offering it would promise an action that does
    /// nothing.
    /// </summary>
    public static string? ActionablePath(ReportItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return IsPolicyRow(item) || IsPendingRow(item) ? PathOf(item) : null;
    }

    private static string? PathOf(ReportItem item)
    {
        var path = Field(item, "path");
        return string.IsNullOrWhiteSpace(path) ? null : path;
    }

    /// <summary>The localization key for the message that describes a mutation outcome.</summary>
    public static string ResultMessageKey(FirewallMutationResult result) => result switch
    {
        FirewallMutationResult.Applied => "FirewallActionApplied",
        FirewallMutationResult.ServiceUnavailable => "FirewallActionUnavailable",
        FirewallMutationResult.Unauthorized => "FirewallActionUnauthorized",
        FirewallMutationResult.NotSupported => "FirewallActionNotSupported",
        FirewallMutationResult.Rejected => "FirewallActionRejected",
        _ => "FirewallActionRejected",
    };

    /// <summary>
    /// The localization key for the outcome of arming the machine. Success is reported
    /// distinctly from a saved policy: it is the moment stored blocks begin filtering real
    /// traffic, which is the one state change a user must not have to infer.
    /// </summary>
    public static string EnableEnforcementMessageKey(
        FirewallMutationResult result,
        FirewallEnforcementState observedState) =>
        result == FirewallMutationResult.Applied && observedState == FirewallEnforcementState.Active
            ? "FirewallEnforcementEnabled"
            : result == FirewallMutationResult.Applied
                ? "FirewallEnforcementNotActive"
                : ResultMessageKey(result);

    /// <summary>
    /// Compatibility overload for callers that did not observe a runtime status. It is
    /// intentionally conservative: without an observed <c>Active</c> state, UI must not say
    /// filtering started.
    /// </summary>
    public static string EnableEnforcementMessageKey(FirewallMutationResult result) =>
        EnableEnforcementMessageKey(result, FirewallEnforcementState.Degraded);

    /// <summary>
    /// Like <see cref="ResultMessageKey"/>, but a successfully saved BLOCK is reported as
    /// "saved, not yet enforced" when enforcement is off — a block only filters traffic
    /// once enforcement is enabled, so the user is told instead of assuming it is live.
    /// </summary>
    public static string OutcomeMessageKey(
        FirewallMutationResult result, bool isBlock, bool enforcementEnabled) =>
        result == FirewallMutationResult.Applied && isBlock && !enforcementEnabled
            ? "FirewallActionAppliedNotEnforced"
            : ResultMessageKey(result);

    private static string? Field(ReportItem item, string key) =>
        item.Fields.TryGetValue(key, out var value) ? value : null;
}
