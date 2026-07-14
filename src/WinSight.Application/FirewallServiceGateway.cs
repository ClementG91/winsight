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

/// <summary>
/// Talks to the local firewall service over the authenticated pipe and projects the
/// reply into a <see cref="FirewallServiceView"/>. It never mutates policy here; the
/// dashboard is a read-only consumer in this increment. Transport faults (no service,
/// timeout, malformed reply) collapse to <see cref="FirewallServiceView.Unavailable"/>.
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
