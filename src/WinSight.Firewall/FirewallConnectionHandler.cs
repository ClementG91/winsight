namespace WinSight.Firewall;

/// <summary>
/// Serves a single authenticated request/response exchange over an already-connected
/// duplex stream. It is transport-agnostic (named pipe in production, an in-memory pair
/// in tests) so the exchange logic is verified without any privilege or OS pipe.
///
/// The caller is authenticated by the transport BEFORE this runs; the decision is passed
/// in as <paramref name="callerAuthorised"/>. A frame that cannot even be parsed yields
/// no reply (there is no request id to echo, and the strict codec forbids a malformed
/// response), so the connection is simply closed.
/// </summary>
public sealed class FirewallConnectionHandler
{
    private readonly FirewallRequestDispatcher _dispatcher;

    public FirewallConnectionHandler(FirewallRequestDispatcher dispatcher) =>
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

    public async Task HandleAsync(
        Stream stream,
        bool callerAuthorised,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        FirewallCommandRequest request;
        try
        {
            request = await FirewallProtocolCodec.ReadRequestAsync(stream, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (FirewallProtocolException)
        {
            // Unparseable or over-sized frame: no valid reply is possible, so close.
            return;
        }

        var response = await _dispatcher.DispatchAsync(request, callerAuthorised, cancellationToken)
            .ConfigureAwait(false);

        try
        {
            await FirewallProtocolCodec.WriteResponseAsync(stream, response, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (IOException)
        {
            // The peer disconnected before it read the reply; nothing more to do.
        }
    }
}
