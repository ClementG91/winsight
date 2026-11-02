using System.Security;

using WinSight.Firewall;

namespace WinSight.Application;

/// <summary>One authenticated status observation, with no policy enumeration or mutation.</summary>
public static class FirewallIpcReadOnlyProbe
{
    public static async Task<bool> RunAsync(
        IFirewallServiceClient client, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        // This total bound also covers the client's separately bounded connect/write/read phases.
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        var request = new FirewallCommandRequest(
            FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus);
        try
        {
            var response = await client.SendAsync(request, TimeSpan.FromSeconds(3), deadline.Token)
                .ConfigureAwait(false);
            if (!response.Success || response.Error != FirewallProtocolError.None
                || response.RequestId != request.RequestId || response.ProtocolVersion != request.ProtocolVersion
                || response.Status is null)
            {
                return false;
            }
            // Reuse the codec's complete status invariants for injected clients too. These bounded
            // bytes are discarded locally; this neither sends another IPC request nor changes state.
            await FirewallProtocolCodec.WriteResponseAsync(Stream.Null, response, deadline.Token)
                .ConfigureAwait(false);
            deadline.Token.ThrowIfCancellationRequested();
            return true;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }
        catch (Exception failure) when (failure is IOException or TimeoutException
            or UnauthorizedAccessException or SecurityException)
        {
            return false;
        }
    }
}
