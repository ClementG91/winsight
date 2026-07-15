using WinSight.Firewall;

namespace WinSight.FirewallService;

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
public sealed class WfpOutboundFirewallEngine : IOutboundFirewallEngine, IWinSightFirewallCleanup
{
    /// <summary>WFP is available on every supported Windows baseline.</summary>
    public bool IsSupported => true;

    public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
        cancellationToken.ThrowIfCancellationRequested();

        WfpProvisioning.Provision();
        if (policy.Action == OutboundAction.Block)
        {
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

    public async Task CleanupWinSightAsync(
        IReadOnlyList<AppFirewallPolicy> knownPolicies,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(knownPolicies);
        foreach (var policy in knownPolicies)
        {
            await RemoveAsync(policy.ExecutablePath, cancellationToken).ConfigureAwait(false);
        }
        cancellationToken.ThrowIfCancellationRequested();
        WfpProvisioning.RemovePermitFilter();
        WfpProvisioning.Deprovision();
    }
}
