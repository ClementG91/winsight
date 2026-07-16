using WinSight.Firewall;

namespace WinSight.Application;

/// <summary>
/// A read-only view of the firewall service for the dashboard: whether the privileged
/// service is reachable, its mode, whether enforcement is active, and the stored
/// policies. When the service is not installed or not running, the view degrades to
/// "unavailable, audit-only" instead of surfacing an error, so the dashboard stays
/// usable and never implies the machine is being filtered when it is not.
/// </summary>
/// <param name="Pending">
/// Applications seen reaching the network that have never been ruled on, newest first.
/// </param>
/// <param name="UnrecordedApps">
/// How many further apps the service could not record. Surfaced rather than dropped so the list is
/// never presented as complete when it is not.
/// </param>
public sealed record FirewallServiceView(
    bool ServiceAvailable,
    OutboundFirewallMode Mode,
    bool EnforcementEnabled,
    IReadOnlyList<AppFirewallPolicy> Policies,
    IReadOnlyList<PendingOutboundApp> Pending,
    int UnrecordedApps = 0)
{
    public static FirewallServiceView Unavailable { get; } =
        new(false, OutboundFirewallMode.AuditOnly, EnforcementEnabled: false, [], []);
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

    /// <summary>
    /// The machine cannot do what was asked — it has no usable outbound engine, so
    /// enforcement could never filter. Distinct from <see cref="Rejected"/> because telling
    /// an operator "rejected" when the real answer is "this machine cannot filter at all"
    /// invites them to believe a retry would protect them.
    /// </summary>
    NotSupported,

    /// <summary>The service rejected the request (invalid or internal failure).</summary>
    Rejected,
}

/// <summary>
/// Talks to the local firewall service over the authenticated pipe. It projects a status
/// read into a <see cref="FirewallServiceView"/>, and requests policy mutations
/// (set/remove one app, emergency-disable) that the privileged service authorises by the
/// caller's Windows identity. Transport faults (no service, timeout, malformed reply)
/// collapse to <see cref="FirewallServiceView.Unavailable"/> or
/// <see cref="FirewallMutationResult.ServiceUnavailable"/>, so the dashboard never implies
/// the machine is filtered when it is not. Enabling enforcement is requested here too, but
/// the request is only a request: the privileged service performs the WFP mutation and
/// authorises it by the caller's Windows identity, so an unprivileged dashboard is refused
/// and only an elevated one can arm the machine.
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
            var pending = await ListAllPendingAsync(cancellationToken).ConfigureAwait(false);
            return new FirewallServiceView(
                ServiceAvailable: true,
                status.Status.Mode,
                status.Status.EnforcementEnabled,
                policies,
                pending,
                status.Status.UnrecordedApps);
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

    /// <summary>
    /// Arms the machine: promotes it to enforcement so the stored blocks start filtering.
    /// The service refuses this unless the caller is elevated, and refuses it outright when
    /// the machine has no usable engine, so a success here means traffic really is filtered.
    /// </summary>
    public Task<FirewallMutationResult> EnableEnforcementAsync(CancellationToken cancellationToken = default) =>
        MutateAsync(
            new FirewallCommandRequest(
                FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.EnableEnforcement),
            cancellationToken);

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
            return response.Error switch
            {
                FirewallProtocolError.Unauthorized => FirewallMutationResult.Unauthorized,
                FirewallProtocolError.NotSupported => FirewallMutationResult.NotSupported,
                _ => FirewallMutationResult.Rejected,
            };
        }
        catch (Exception ex) when (ex is TimeoutException or FirewallProtocolException or IOException)
        {
            return FirewallMutationResult.ServiceUnavailable;
        }
    }

    private async Task<IReadOnlyList<PendingOutboundApp>> ListAllPendingAsync(CancellationToken cancellationToken)
    {
        var all = new List<PendingOutboundApp>();
        var offset = 0;

        // Bounded for the same reason as the policy list: a misbehaving service that never
        // advances the offset must not spin the dashboard forever.
        const int maxPages = (PendingOutboundLog.MaxPendingApps / FirewallProtocolCodec.MaxPoliciesPerMessage) + 4;
        for (var page = 0; page < maxPages; page++)
        {
            var response = await SendAsync(
                Request(FirewallCommand.ListPending, offset: offset, limit: FirewallProtocolCodec.MaxPoliciesPerMessage),
                cancellationToken).ConfigureAwait(false);
            if (!response.Success || response.Pending is null)
            {
                break;
            }

            all.AddRange(response.Pending);
            if (response.NextOffset is not { } next || next <= offset)
            {
                break;
            }
            offset = next;
        }
        return all;
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
