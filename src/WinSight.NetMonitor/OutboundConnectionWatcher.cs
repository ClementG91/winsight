using Microsoft.Diagnostics.Tracing.Session;

namespace WinSight.NetMonitor;

/// <summary>An outbound connection attempt observed via ETW, as it happens.</summary>
/// <param name="ProcessId">The process that reached out.</param>
/// <param name="RemoteAddress">The destination address.</param>
/// <param name="RemotePort">The destination port.</param>
public sealed record OutboundConnectionEvent(int ProcessId, string RemoteAddress, int RemotePort)
{
    /// <summary>The destination as an operator reads it.</summary>
    public string Remote => $"{RemoteAddress}:{RemotePort}";
}

/// <summary>
/// Real-time visibility of outbound connection attempts via an ETW session on the
/// Microsoft-Windows-Kernel-Network provider: every time a process reaches out, as it happens.
/// Requires Administrator (creating an ETW session is privileged); the caller surfaces that. The
/// session is stopped cleanly on cancellation.
/// </summary>
/// <remarks>
/// The event shape here was read off a live machine rather than inferred, because two details are
/// easy to get wrong and neither fails loudly:
///
/// <b>Only <see cref="ConnectionAttemptedId"/> is outbound.</b> The same task also emits
/// <c>Connectionaccepted</c> (id 15) for <em>inbound</em> connections. Matching on the word
/// "connect", or on the task alone, silently reports every inbound connection as if the local
/// process had reached out.
///
/// <b>The process is in the payload, not the header.</b> These events are emitted from whatever
/// context the stack happens to be in, so <c>TraceEvent.ProcessID</c> is not the connecting
/// process; the <c>PID</c> field is. Reading the header would attribute connections to the wrong
/// program, which for a tool whose whole job is attribution is the worst possible failure.
///
/// The provider does not split IPv4 and IPv6 into separate opcodes — <c>daddr</c> carries either
/// family — so one id covers both.
/// </remarks>
public sealed class OutboundConnectionWatcher
{
    private const string KernelNetworkProvider = "Microsoft-Windows-Kernel-Network";

    /// <summary>KERNEL_NETWORK_TASK_TCPIP/Connectionattempted, the outbound connect.</summary>
    private const int ConnectionAttemptedId = 12;

    /// <summary>
    /// Opens the ETW session and invokes <paramref name="onEvent"/> for each outbound connection
    /// attempt until cancelled. Blocking; run on its own thread. Throws
    /// UnauthorizedAccessException when not elevated.
    /// </summary>
    public void Watch(Action<OutboundConnectionEvent> onEvent, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(onEvent);

        using var session = new TraceEventSession($"WinSight-Outbound-{Environment.ProcessId}");
        using var stop = token.Register(() =>
        {
            try
            {
                session.Stop();
            }
            catch (Exception)
            {
                // Session already gone, nothing to do.
            }
        });

        session.EnableProvider(KernelNetworkProvider);
        session.Source.Dynamic.All += data =>
        {
            if ((int)data.ID != ConnectionAttemptedId)
            {
                return;
            }
            if (TryRead(data.PayloadByName("PID"), out var pid) &&
                data.PayloadByName("daddr") is { } address &&
                TryRead(data.PayloadByName("dport"), out var port))
            {
                var remote = Convert.ToString(address, System.Globalization.CultureInfo.InvariantCulture);
                if (!string.IsNullOrWhiteSpace(remote))
                {
                    onEvent(new OutboundConnectionEvent(pid, remote, port));
                }
            }
        };
        session.Source.Process(); // blocks until the session is stopped
    }

    private static bool TryRead(object? value, out int result)
    {
        result = value switch
        {
            int i => i,
            uint u => (int)u,
            long l => (int)l,
            ulong ul => (int)ul,
            ushort s => s,
            short s => s,
            byte b => b,
            string text when int.TryParse(text, System.Globalization.CultureInfo.InvariantCulture, out var n) => n,
            _ => -1,
        };
        return result >= 0;
    }
}
