using System.IO.Pipes;

namespace WinSight.Firewall;

/// <summary>
/// Connects to the local firewall service pipe, sends one command and reads the reply.
/// The unprivileged dashboard uses this; it never touches the policy store or WFP
/// directly. The client validates the reply through the same strict codec, so a
/// malformed or over-sized frame is rejected rather than trusted.
/// </summary>
public sealed class FirewallServiceClient
{
    private readonly string _pipeName;

    public FirewallServiceClient(string? pipeName = null) =>
        _pipeName = string.IsNullOrWhiteSpace(pipeName) ? FirewallServiceSecurity.DefaultPipeName : pipeName;

    /// <summary>
    /// Sends <paramref name="request"/> and returns the service reply. Throws
    /// <see cref="TimeoutException"/> if the service does not accept the connection in
    /// time and <see cref="FirewallProtocolException"/> for an invalid reply frame.
    /// </summary>
    public async Task<FirewallCommandResponse> SendAsync(
        FirewallCommandRequest request,
        TimeSpan connectTimeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        await using var client = new NamedPipeClientStream(
            ".",
            _pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);

        try
        {
            await client.ConnectAsync(connectTimeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            throw new TimeoutException("The WinSight firewall service did not respond.");
        }

        await FirewallProtocolCodec.WriteRequestAsync(client, request, cancellationToken).ConfigureAwait(false);
        return await FirewallProtocolCodec.ReadResponseAsync(client, cancellationToken).ConfigureAwait(false);
    }
}
