namespace WinSight.Application;

/// <summary>
/// Reads the outbound-firewall service's posture, and nothing else.
/// </summary>
/// <remarks>
/// <see cref="FirewallServiceGateway"/> can both read posture and request mutations, which is
/// right for the dashboard and wrong for any caller that is only ever allowed to look. Handing
/// such a caller this interface instead makes the restriction structural: it holds no reference
/// it could call <c>SetPolicyAsync</c> or <c>EnableEnforcementAsync</c> through, so "read-only"
/// stops depending on nobody adding the wrong line later.
///
/// This is a second layer, not the only one. The privileged service authorises by the caller's
/// Windows identity and refuses every mutation to a caller holding read capability, so an
/// unelevated consumer could not arm the machine even through the full gateway.
/// </remarks>
public interface IFirewallPostureReader
{
    Task<FirewallServiceView> GetViewAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Exposes a gateway's posture read while keeping the gateway itself out of the caller's reach.
/// </summary>
public sealed class FirewallPostureReader : IFirewallPostureReader
{
    // Private, and never returned: the whole point of the wrapper is that a caller given the
    // interface cannot reach back to the mutating surface.
    private readonly FirewallServiceGateway _gateway;

    public FirewallPostureReader(FirewallServiceGateway gateway)
    {
        _gateway = gateway ?? throw new ArgumentNullException(nameof(gateway));
    }

    public Task<FirewallServiceView> GetViewAsync(CancellationToken cancellationToken = default) =>
        _gateway.GetViewAsync(cancellationToken);
}
