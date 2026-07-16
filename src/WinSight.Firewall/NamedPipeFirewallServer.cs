using System.IO.Pipes;
using System.Security.Principal;

namespace WinSight.Firewall;

/// <summary>
/// Hosts the outbound-firewall command endpoint over a hardened local named pipe. Each
/// connection is authenticated (the connected Windows identity is verified while
/// impersonating the client) and serves exactly one request/response exchange, one
/// connection at a time. The privileged service owns this host; the dashboard is a
/// client and never mutates policy directly.
///
/// This host performs no WFP mutation. It is the Phase 2 increment-1 transport around
/// the audit-only dispatcher; enabling enforcement is separate, later and gated.
/// </summary>
public sealed class NamedPipeFirewallServer : IFirewallServiceListener
{
    private readonly FirewallConnectionHandler _handler;
    private readonly string _pipeName;
    private readonly Func<NamedPipeServerStream, FirewallCallerCapability> _authorise;
    private readonly Func<PipeSecurity> _securityFactory;

    /// <param name="handler">The exchange handler wrapping the dispatcher.</param>
    /// <param name="pipeName">Pipe name; defaults to the WinSight firewall pipe.</param>
    /// <param name="authorise">
    /// Authorisation decision for a connected client. Defaults to verifying the
    /// impersonated Windows identity. Tests may inject a deterministic decision.
    /// </param>
    /// <param name="securityFactory">
    /// Produces the pipe ACL for each server instance. Defaults to the hardened ACL.
    /// Tests may inject an ACL scoped to the current user for non-interactive runners.
    /// </param>
    public NamedPipeFirewallServer(
        FirewallConnectionHandler handler,
        string? pipeName = null,
        Func<NamedPipeServerStream, bool>? authorise = null,
        Func<PipeSecurity>? securityFactory = null,
        Func<NamedPipeServerStream, FirewallCallerCapability>? capabilityAuthorise = null)
    {
        _handler = handler ?? throw new ArgumentNullException(nameof(handler));
        _pipeName = string.IsNullOrWhiteSpace(pipeName) ? FirewallServiceSecurity.DefaultPipeName : pipeName;
        _authorise = capabilityAuthorise ?? (authorise is null
            ? DefaultAuthorise
            : server => authorise(server) ? FirewallCallerCapability.MutateMachinePolicy : FirewallCallerCapability.None);
        _securityFactory = securityFactory ?? FirewallServiceSecurity.CreateHardenedSecurity;
    }

    /// <summary>Accepts connections until cancelled. Per-connection faults are isolated.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await ServeOnceAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (IOException)
            {
                // A broken connection must not take the service down; accept the next.
            }
        }
    }

    /// <summary>
    /// Accepts and serves a single connection. Exposed so the exchange can be tested
    /// end-to-end over a real pipe without the accept loop.
    /// </summary>
    public async Task ServeOnceAsync(CancellationToken cancellationToken)
    {
        var security = _securityFactory();
        await using var server = NamedPipeServerStreamAcl.Create(
            _pipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 0,
            outBufferSize: 0,
            security);

        await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);

        var capability = _authorise(server);
        await _handler.HandleAsync(server, capability, cancellationToken).ConfigureAwait(false);

        if (server.IsConnected)
        {
            server.Disconnect();
        }
    }

    private static FirewallCallerCapability DefaultAuthorise(NamedPipeServerStream server)
    {
        try
        {
            var capability = FirewallCallerCapability.None;
            server.RunAsClient(() =>
            {
                using var identity = WindowsIdentity.GetCurrent();
                capability = FirewallServiceSecurity.GetCallerCapability(identity);
            });
            return capability;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            // Fail closed: if the client identity cannot be established, deny.
            return FirewallCallerCapability.None;
        }
    }
}
