using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace WinSight.NetMonitor;

/// <summary>An outbound connection attempt observed via ETW, already attributed to its program.</summary>
/// <param name="ProcessId">The process that reached out.</param>
/// <param name="ExecutablePath">That process's executable, the identity a policy is keyed on.</param>
/// <param name="RemoteAddress">The destination address.</param>
/// <param name="RemotePort">The destination port.</param>
public sealed record OutboundConnectionEvent(
    int ProcessId,
    string ExecutablePath,
    string RemoteAddress,
    int RemotePort)
{
    /// <summary>The destination as an operator reads it.</summary>
    public string Remote => $"{RemoteAddress}:{RemotePort}";
}

/// <summary>
/// Reports outbound connections as they happen, each already attributed to the program that made
/// it. Requires Administrator (a kernel trace session is privileged); the caller surfaces that. The
/// session is stopped cleanly on cancellation.
/// </summary>
/// <remarks>
/// <b>Why the kernel session.</b> The obvious provider, Microsoft-Windows-Kernel-Network, reports
/// connections but not who made them: it carries a process id, and nothing else. Turning that id
/// into an executable meant asking the operating system after the fact, which does not work —
/// ETW delivers a second or more late, and a program that reaches out and exits immediately, which
/// is precisely the interesting case, is already gone. That version reported nothing at all,
/// silently, and every unit test passed. The kernel session solves it at the source: process start
/// carries the command line, so the path is captured while the process is alive, and connections
/// arrive on the same ordered stream already attributed. Its network events are also decoded
/// properly, rather than as a packed address integer and a port in network byte order that reads
/// negative.
///
/// <b>Why its own session, not the NT Kernel Logger.</b> The kernel events used to be reachable
/// only through one machine-wide session, which would have meant taking a resource other tools
/// need and failing whenever something else held it. Windows 8 lifted that: a privately named
/// session can enable the same providers, and several may coexist. Verified on a live machine —
/// this watcher collected process and connection events normally while the NT Kernel Logger was
/// already held by something else. WinSight therefore never competes for it.
/// </remarks>
public sealed class OutboundConnectionWatcher
{
    /// <summary>
    /// Opens the trace session and invokes <paramref name="onEvent"/> for each attributed outbound
    /// connection until cancelled. Blocking; run on its own thread. Throws
    /// UnauthorizedAccessException when not elevated.
    /// </summary>
    public void Watch(Action<OutboundConnectionEvent> onEvent, CancellationToken token) =>
        Watch(onEvent, onUnattributed: null, token);

    /// <summary>
    /// As above, additionally reporting connections whose process could not be named well enough to
    /// rule on — with its image name when the kernel gave one, and the process id either way.
    /// </summary>
    /// <remarks>
    /// Dropping an unrulable connection is right; dropping it <i>silently</i> left the service's
    /// own "unattributed" counter permanently at zero on a machine that was losing connections. The
    /// caller can now distinguish a quiet network from a blind watcher.
    /// </remarks>
    public void Watch(
        Action<OutboundConnectionEvent> onEvent,
        Action<int, string?>? onUnattributed,
        CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(onEvent);

        var index = new ProcessPathIndex();
        // A private name, so WinSight never takes the shared NT Kernel Logger from another tool.
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

        // Process gives the command line the attribution depends on; NetworkTCPIP gives the
        // connections. One session, so the two arrive in order and a connection is never seen
        // before the process that made it.
        session.EnableKernelProvider(
            KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.NetworkTCPIP);

        // The start group covers processes already running when the session opens, not just new
        // ones, so a long-lived program's connections are attributed from the first event.
        session.Source.Kernel.ProcessStartGroup += process =>
        {
            var path = ProcessCommandLine.ExtractExecutablePath(process.CommandLine, process.ImageFileName);
            if (path is not null)
            {
                index.Started(process.ProcessID, path);
            }
            // No readable path is not the same as no identity. Measured live, this is where
            // powershell.exe, "cmd /c …" and node land — launched by bare name through the search
            // path. The name cannot carry a firewall rule, but it can tell an operator which
            // program's traffic went unruled instead of leaving them a bare process id.
            else if (!string.IsNullOrWhiteSpace(process.ImageFileName))
            {
                index.StartedWithoutPath(process.ProcessID, process.ImageFileName);
            }
        };
        session.Source.Kernel.ProcessStop += process =>
        {
            index.Stopped(process.ProcessID, process.TimeStamp.ToUniversalTime());
            index.Prune(process.TimeStamp.ToUniversalTime());
        };

        session.Source.Kernel.TcpIpConnect += connect =>
        {
            // Only a real path is emitted as an attributed connection: every policy is keyed on the
            // executable, and a rule matching a bare name would apply to every program sharing it.
            // Anything else is reported as unattributed rather than discarded — a connection nobody
            // could name is a fact about the machine, not an absence of one.
            if (index.Resolve(connect.ProcessID) is { } path)
            {
                onEvent(new OutboundConnectionEvent(
                    connect.ProcessID, path, connect.daddr.ToString(), connect.dport));
            }
            else
            {
                onUnattributed?.Invoke(connect.ProcessID, index.ResolveImage(connect.ProcessID)?.Value);
            }
        };

        session.Source.Process(); // blocks until the session is stopped
    }
}
