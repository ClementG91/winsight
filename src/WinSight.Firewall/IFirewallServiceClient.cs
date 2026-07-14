namespace WinSight.Firewall;

/// <summary>
/// The client side of the firewall service pipe. Abstracted so callers (the dashboard
/// gateway, tests) can depend on the exchange without a real pipe or a running service.
/// </summary>
public interface IFirewallServiceClient
{
    /// <summary>
    /// Sends one command and returns the reply. Throws <see cref="TimeoutException"/>
    /// when the service does not accept the connection in time.
    /// </summary>
    Task<FirewallCommandResponse> SendAsync(
        FirewallCommandRequest request,
        TimeSpan connectTimeout,
        CancellationToken cancellationToken = default);
}
