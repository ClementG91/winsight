using WinSight.Firewall;

namespace WinSight.FirewallService;

/// <summary>
/// The mandatory service-side WFP truth boundary. Implementations reconcile from the
/// complete desired policy set, verify the complete native state, and remove every
/// WinSight-owned object without relying on policy-store paths.
/// </summary>
public interface IWinSightWfpReconciler
{
    bool IsSupported { get; }

    Task ReconcileExactAsync(
        IReadOnlyList<AppFirewallPolicy> policies,
        CancellationToken cancellationToken = default);

    Task<bool> VerifyExactAsync(
        IReadOnlyList<AppFirewallPolicy> policies,
        CancellationToken cancellationToken = default);

    Task CleanupAllAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// The real WFP-backed outbound firewall engine. It maps per-application policies to WFP
/// filters: a <see cref="OutboundAction.Block"/> policy installs a per-app block filter
/// (IPv4 and IPv6), while <see cref="OutboundAction.Allow"/> and
/// <see cref="OutboundAction.Ask"/> ensure the app is not blocked. It idempotently
/// provisions the WinSight provider/sublayer, so applying a policy is self-contained. Only
/// the privileged service uses this; it is never wired into the unprivileged dashboard.
///
/// The service authority creates this backend lazily, only after trusted storage proves
/// that enforcement or narrowly scoped WinSight cleanup requires native access.
/// </summary>
public sealed class WfpOutboundFirewallEngine : IOutboundFirewallEngine, IWinSightWfpReconciler
{
    /// <summary>WFP is available on every supported Windows baseline.</summary>
    public bool IsSupported => true;

    public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
        cancellationToken.ThrowIfCancellationRequested();

        if (policy.Enabled && policy.Action == OutboundAction.Block)
        {
            WfpProvisioning.Provision();
            WfpProvisioning.AddBlockFilter(policy.ExecutablePath);
        }
        else
        {
            // Allow / Ask: make sure any earlier block for this app is lifted.
            WfpProvisioning.RemoveBlockFilter(policy.ExecutablePath);
        }
        return Task.CompletedTask;
    }

    public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        cancellationToken.ThrowIfCancellationRequested();

        WfpProvisioning.RemoveBlockFilter(executablePath);
        return Task.CompletedTask;
    }

    public Task ReconcileExactAsync(
        IReadOnlyList<AppFirewallPolicy> policies,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policies);
        cancellationToken.ThrowIfCancellationRequested();
        WfpProvisioning.ReconcileExact(policies);
        return Task.CompletedTask;
    }

    public Task<bool> VerifyExactAsync(
        IReadOnlyList<AppFirewallPolicy> policies,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policies);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(WfpProvisioning.VerifyExact(policies));
    }

    public Task CleanupAllAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        WfpProvisioning.CleanupAll();
        return Task.CompletedTask;
    }
}
