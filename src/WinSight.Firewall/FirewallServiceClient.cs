using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace WinSight.Firewall;

/// <summary>
/// Connects to the local firewall service pipe, sends one command and reads the reply.
/// The unprivileged dashboard uses this; it never touches the policy store or WFP
/// directly. The client validates the reply through the same strict codec, so a
/// malformed or over-sized frame is rejected rather than trusted. Before sending any
/// byte, it also proves that the connected pipe object is owned by LocalSystem.
/// </summary>
public sealed class FirewallServiceClient : IFirewallServiceClient
{
    private readonly string _pipeName;
    private readonly Action<NamedPipeClientStream> _validatePeer;

    public FirewallServiceClient(string? pipeName = null)
        : this(pipeName, ValidateLocalSystemPeer)
    {
    }

    internal FirewallServiceClient(
        string? pipeName,
        Action<NamedPipeClientStream> validatePeer)
    {
        _pipeName = string.IsNullOrWhiteSpace(pipeName) ? FirewallServiceSecurity.DefaultPipeName : pipeName;
        _validatePeer = validatePeer ?? throw new ArgumentNullException(nameof(validatePeer));
    }

    /// <summary>
    /// Sends <paramref name="request"/> and returns the service reply. Throws
    /// <see cref="TimeoutException"/> if the service does not accept the connection in
    /// time, <see cref="FirewallPeerValidationException"/> when the peer or response
    /// correlation cannot be proven, <see cref="FirewallLegacyPeerClosedException"/> only
    /// when the authenticated peer closes before the first response byte, and
    /// <see cref="FirewallProtocolException"/> for an invalid reply frame.
    /// </summary>
    public async Task<FirewallCommandResponse> SendAsync(
        FirewallCommandRequest request,
        TimeSpan connectTimeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Impersonation is required so the service can verify the caller's real Windows
        // identity via RunAsClient. Without it the server sees an anonymous token and
        // denies the request, which the gateway then reports as an unavailable service.
        await using var client = new NamedPipeClientStream(
            ".",
            _pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous,
            TokenImpersonationLevel.Impersonation);

        try
        {
            await client.ConnectAsync(connectTimeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            throw new TimeoutException("The WinSight firewall service did not respond.");
        }

        // The pipe name is public to interactive users, so connecting by name is not
        // authentication. Prove the connected kernel object's owner before disclosing
        // even a read-only request to it.
        _validatePeer(client);
        await WithDeadlineAsync(
            token => FirewallProtocolCodec.WriteRequestAsync(client, request, token),
            connectTimeout,
            cancellationToken).ConfigureAwait(false);
        FirewallCommandResponse response;
        try
        {
            response = await WithDeadlineAsync(
                token => FirewallProtocolCodec.ReadResponseAsync(client, token),
                connectTimeout,
                cancellationToken).ConfigureAwait(false);
        }
        catch (FirewallProtocolException ex) when (ex.Error == FirewallProtocolError.UnsupportedVersion)
        {
            throw new FirewallPeerValidationException();
        }
        if (response.RequestId != request.RequestId
            || response.ProtocolVersion != request.ProtocolVersion)
        {
            throw new FirewallPeerValidationException();
        }
        return response;
    }

    private static async Task WithDeadlineAsync(
        Func<CancellationToken, Task> operation,
        TimeSpan timeout,
        CancellationToken callerCancellation)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(callerCancellation);
        deadline.CancelAfter(timeout);
        try
        {
            await operation(deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!callerCancellation.IsCancellationRequested)
        {
            throw new TimeoutException("The WinSight firewall service did not respond.");
        }
    }

    private static async Task<T> WithDeadlineAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        TimeSpan timeout,
        CancellationToken callerCancellation)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(callerCancellation);
        deadline.CancelAfter(timeout);
        try
        {
            return await operation(deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!callerCancellation.IsCancellationRequested)
        {
            throw new TimeoutException("The WinSight firewall service did not respond.");
        }
    }

    private static void ValidateLocalSystemPeer(NamedPipeClientStream client)
    {
        nint securityDescriptor = 0;
        try
        {
            var result = NativeMethods.GetSecurityInfo(
                client.SafePipeHandle,
                SeKernelObject,
                OwnerSecurityInformation,
                out var ownerPointer,
                0,
                0,
                0,
                out securityDescriptor);
            if (result != 0 || ownerPointer == 0 || securityDescriptor == 0)
            {
                throw new FirewallPeerValidationException();
            }

            var owner = new SecurityIdentifier(ownerPointer);
            if (!owner.IsWellKnown(WellKnownSidType.LocalSystemSid))
            {
                throw new FirewallPeerValidationException();
            }
        }
        catch (FirewallPeerValidationException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException
            or UnauthorizedAccessException
            or InvalidOperationException
            or ObjectDisposedException
            or NotSupportedException
            or ArgumentException
            or System.Security.SecurityException)
        {
            throw new FirewallPeerValidationException();
        }
        finally
        {
            if (securityDescriptor != 0)
            {
                _ = NativeMethods.LocalFree(securityDescriptor);
            }
        }
    }

    private const int SeKernelObject = 6;
    private const uint OwnerSecurityInformation = 0x00000001;

    private static class NativeMethods
    {
        [DllImport("advapi32.dll", ExactSpelling = true)]
        internal static extern uint GetSecurityInfo(
            SafePipeHandle handle,
            int objectType,
            uint securityInformation,
            out nint owner,
            nint group,
            nint dacl,
            nint sacl,
            out nint securityDescriptor);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        internal static extern nint LocalFree(nint memory);
    }
}
