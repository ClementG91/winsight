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
        CancellationToken cancellationToken = default) =>
        await HandleAsync(stream, callerAuthorised ? FirewallCallerCapability.MutateMachinePolicy : FirewallCallerCapability.None,
            cancellationToken).ConfigureAwait(false);

    public async Task HandleAsync(
        Stream stream,
        FirewallCallerCapability capability,
        CancellationToken cancellationToken = default)
        => await HandleAsync(
            stream,
            capability,
            Timeout.InfiniteTimeSpan,
            Timeout.InfiniteTimeSpan,
            cancellationToken).ConfigureAwait(false);

    public async Task HandleAsync(
        Stream stream,
        FirewallCallerCapability capability,
        TimeSpan requestReadTimeout,
        TimeSpan responseWriteTimeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        FirewallCommandRequest request;
        try
        {
            using var readCancellation = CreateIoCancellation(
                requestReadTimeout, cancellationToken);
            request = await FirewallProtocolCodec.ReadRequestAsync(stream, readCancellation.Token)
                .ConfigureAwait(false);
        }
        catch (FirewallProtocolException)
        {
            // Unparseable or over-sized frame: no valid reply is possible, so close.
            return;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // A silent peer must not monopolise the service's only pipe instance.
            return;
        }

        // Deliberately use only service-lifetime cancellation here. A WFP transition is
        // not an I/O wait and must not be abandoned merely because a peer is slow.
        var response = await _dispatcher.DispatchAsync(request, capability, cancellationToken)
            .ConfigureAwait(false);

        try
        {
            using var writeCancellation = CreateIoCancellation(
                responseWriteTimeout, cancellationToken);
            await FirewallProtocolCodec.WriteResponseAsync(stream, response, writeCancellation.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // The completed transition is authoritative even when its peer stops reading.
        }
        catch (IOException)
        {
            // The peer disconnected before it read the reply; nothing more to do.
        }
    }

    private static CancellationTokenSource CreateIoCancellation(
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (timeout != Timeout.InfiniteTimeSpan)
        {
            linked.CancelAfter(timeout);
        }
        return linked;
    }
}
