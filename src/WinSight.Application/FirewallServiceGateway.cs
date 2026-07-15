using WinSight.Firewall;

namespace WinSight.Application;

/// <summary>
/// A read-only view of the firewall service for the dashboard: whether the privileged
/// service is reachable, its mode, whether enforcement is active, and the stored
/// policies. When the service is not installed or not running, the view degrades to
/// "unavailable, audit-only" instead of surfacing an error, so the dashboard stays
/// usable and never implies the machine is being filtered when it is not.
/// </summary>
public sealed record FirewallServiceView(
    bool ServiceAvailable,
    OutboundFirewallMode Mode,
    bool EnforcementEnabled,
    IReadOnlyList<AppFirewallPolicy> Policies)
{
    public static FirewallServiceView Unavailable { get; } =
        new(false, OutboundFirewallMode.AuditOnly, EnforcementEnabled: false, []);
}

/// <summary>Outcome of a firewall policy mutation requested from the dashboard side.</summary>
public enum FirewallMutationResult
{
    /// <summary>The service accepted and applied the change.</summary>
    Applied,

    /// <summary>The service is not installed, not running, or did not reply in time.</summary>
    ServiceUnavailable,

    /// <summary>The caller's Windows identity is not permitted to change policy.</summary>
    Unauthorized,

    /// <summary>The service rejected the request (invalid, unsupported, or internal failure).</summary>
    Rejected,
}

/// <summary>
/// Talks to the local firewall service over the authenticated pipe. It projects a status
/// read into a <see cref="FirewallServiceView"/>, and requests policy mutations
/// (set/remove one app, emergency-disable) that the privileged service authorises by the
/// caller's Windows identity. Transport faults (no service, timeout, malformed reply)
/// collapse to <see cref="FirewallServiceView.Unavailable"/> or
/// <see cref="FirewallMutationResult.ServiceUnavailable"/>, so the dashboard never implies
/// the machine is filtered when it is not. Enabling enforcement itself is not exposed here:
/// that stays a privileged, out-of-band action, not something the unprivileged dashboard
/// can trigger.
/// </summary>
public sealed class FirewallServiceGateway
{
    private static readonly TimeSpan DefaultConnectTimeout = TimeSpan.FromSeconds(2);

    private readonly IFirewallServiceClient _client;
    private readonly TimeSpan _connectTimeout;

    public FirewallServiceGateway(IFirewallServiceClient client, TimeSpan? connectTimeout = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _connectTimeout = connectTimeout ?? DefaultConnectTimeout;
    }

    public async Task<FirewallServiceView> GetViewAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var status = await SendAsync(
                Request(FirewallCommand.GetStatus), cancellationToken).ConfigureAwait(false);
            if (!status.Success || status.Status is null)
            {
                return FirewallServiceView.Unavailable;
            }

            var policies = await ListAllAsync(cancellationToken).ConfigureAwait(false);
            return new FirewallServiceView(
                ServiceAvailable: true,
                status.Status.Mode,
                status.Status.EnforcementEnabled,
                policies);
        }
        catch (Exception ex) when (ex is TimeoutException or FirewallProtocolException or IOException)
        {
            return FirewallServiceView.Unavailable;
        }
    }

    /// <summary>Sets one application's policy (allow/block/ask) and asks the service to apply it.</summary>
    public Task<FirewallMutationResult> SetPolicyAsync(
        AppFirewallPolicy policy, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return MutateAsync(
            new FirewallCommandRequest(
                FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(),
                FirewallCommand.UpsertPolicy, Policy: policy),
            cancellationToken);
    }

    /// <summary>Removes one application's policy and asks the service to lift any filter.</summary>
    public Task<FirewallMutationResult> RemovePolicyAsync(
        string executablePath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        return MutateAsync(
            new FirewallCommandRequest(
                FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(),
                FirewallCommand.RemovePolicy, ExecutablePath: executablePath),
            cancellationToken);
    }

    /// <summary>Returns the machine to audit-only and lifts every filter (fail-safe kill switch).</summary>
    public Task<FirewallMutationResult> EmergencyDisableAsync(CancellationToken cancellationToken = default) =>
        MutateAsync(
            new FirewallCommandRequest(
                FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.EmergencyDisable),
            cancellationToken);

    private async Task<FirewallMutationResult> MutateAsync(
        FirewallCommandRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (response.Success)
            {
                return FirewallMutationResult.Applied;
            }
            return response.Error == FirewallProtocolError.Unauthorized
                ? FirewallMutationResult.Unauthorized
                : FirewallMutationResult.Rejected;
        }
        catch (Exception ex) when (ex is TimeoutException or FirewallProtocolException or IOException)
        {
            return FirewallMutationResult.ServiceUnavailable;
        }
    }

    private async Task<IReadOnlyList<AppFirewallPolicy>> ListAllAsync(CancellationToken cancellationToken)
    {
        var all = new List<AppFirewallPolicy>();
        var offset = 0;

        // Bounded: MaxPolicyCount / page size, with headroom, so a misbehaving service
        // that never advances the offset cannot spin forever.
        const int maxPages = (FirewallPolicyStore.MaxPolicyCount / FirewallProtocolCodec.MaxPoliciesPerMessage) + 4;
        for (var page = 0; page < maxPages; page++)
        {
            var response = await SendAsync(
                Request(FirewallCommand.ListPolicies, offset: offset, limit: FirewallProtocolCodec.MaxPoliciesPerMessage),
                cancellationToken).ConfigureAwait(false);
            if (!response.Success || response.Policies is null)
            {
                break;
            }

            all.AddRange(response.Policies);
            if (response.NextOffset is not { } next || next <= offset)
            {
                break;
            }
            offset = next;
        }

        return all;
    }

    private Task<FirewallCommandResponse> SendAsync(
        FirewallCommandRequest request, CancellationToken cancellationToken) =>
        _client.SendAsync(request, _connectTimeout, cancellationToken);

    private static FirewallCommandRequest Request(
        FirewallCommand command, int? offset = null, int? limit = null) =>
        new(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), command, Offset: offset, Limit: limit);
}
