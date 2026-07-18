namespace WinSight.Firewall;

/// <summary>
/// A long-running local endpoint hosted by the privileged firewall service. Abstracts
/// the concrete transport (a hardened named pipe in production) so the service worker
/// can be hosted and tested without opening a real pipe.
/// </summary>
public interface IFirewallServiceListener
{
    /// <summary>Accepts and serves connections until <paramref name="cancellationToken"/> fires.</summary>
    Task RunAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Optional readiness boundary for listeners that must reserve an OS-owned endpoint
/// before the service may announce that it is listening.
/// </summary>
public interface IFirewallServiceReadiness
{
    Task Ready { get; }
}
