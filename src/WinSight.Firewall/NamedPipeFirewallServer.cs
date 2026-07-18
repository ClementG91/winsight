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
/// This host performs no WFP mutation itself. Explicit privileged transitions are
/// dispatched to the single service-side enforcement coordinator.
/// </summary>
public sealed class NamedPipeFirewallServer : IFirewallServiceListener, IFirewallServiceReadiness
{
    private static readonly TimeSpan DefaultRequestReadTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan DefaultResponseWriteTimeout = TimeSpan.FromSeconds(5);

    private readonly FirewallConnectionHandler _handler;
    private readonly string _pipeName;
    private readonly Func<NamedPipeServerStream, FirewallCallerCapability> _authorise;
    private readonly Func<PipeSecurity> _securityFactory;
    private readonly TimeSpan _requestReadTimeout;
    private readonly TimeSpan _responseWriteTimeout;
    private readonly TaskCompletionSource _ready =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

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
        Func<NamedPipeServerStream, FirewallCallerCapability>? capabilityAuthorise = null,
        TimeSpan? requestReadTimeout = null,
        TimeSpan? responseWriteTimeout = null)
    {
        _handler = handler ?? throw new ArgumentNullException(nameof(handler));
        _pipeName = string.IsNullOrWhiteSpace(pipeName) ? FirewallServiceSecurity.DefaultPipeName : pipeName;
        _authorise = capabilityAuthorise ?? (authorise is null
            ? DefaultAuthorise
            : server => authorise(server) ? FirewallCallerCapability.MutateMachinePolicy : FirewallCallerCapability.None);
        _securityFactory = securityFactory ?? FirewallServiceSecurity.CreateHardenedSecurity;
        _requestReadTimeout = ValidateTimeout(requestReadTimeout ?? DefaultRequestReadTimeout);
        _responseWriteTimeout = ValidateTimeout(responseWriteTimeout ?? DefaultResponseWriteTimeout);
    }

    public Task Ready => _ready.Task;

    /// <summary>Accepts connections until cancelled. Per-connection faults are isolated.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        await using var server = CreateServer();
        _ready.TrySetResult();

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await ServeConnectedClientAsync(server, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
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
        await using var server = CreateServer();
        await ServeConnectedClientAsync(server, cancellationToken).ConfigureAwait(false);
    }

    private NamedPipeServerStream CreateServer()
    {
        var security = _securityFactory();
        return NamedPipeServerStreamAcl.Create(
            _pipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
            inBufferSize: 0,
            outBufferSize: 0,
            security);
    }

    private async Task ServeConnectedClientAsync(
        NamedPipeServerStream server,
        CancellationToken cancellationToken)
    {
        await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var capability = _authorise(server);
            await _handler.HandleAsync(
                server,
                capability,
                _requestReadTimeout,
                _responseWriteTimeout,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (server.IsConnected)
            {
                server.Disconnect();
            }
        }
    }

    private static TimeSpan ValidateTimeout(TimeSpan timeout) =>
        timeout > TimeSpan.Zero && timeout <= TimeSpan.FromMinutes(1)
            ? timeout
            : throw new ArgumentOutOfRangeException(nameof(timeout));

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
