using Microsoft.Diagnostics.Tracing.Session;

namespace WinSight.NetMonitor;

/// <summary>A live DNS query observed via ETW.</summary>
/// <param name="Name">The queried name.</param>
/// <param name="Type">The DNS record type (A, AAAA, ...).</param>
/// <param name="ProcessId">The process that issued the query.</param>
public sealed record DnsQueryEvent(string Name, string Type, int ProcessId);

/// <summary>
/// Real-time DNS visibility via an ETW session on the Microsoft-Windows-DNS-Client
/// provider — every name a process resolves, as it happens (the DNSMonitor "live"
/// mode, complementing the one-shot cache reader). Requires Administrator (creating an
/// ETW session is privileged); the caller surfaces that. The session is stopped
/// cleanly on cancellation.
/// </summary>
public sealed class DnsEtwWatcher
{
    private const string DnsProvider = "Microsoft-Windows-DNS-Client";

    /// <summary>
    /// Opens the ETW session and invokes <paramref name="onEvent"/> for each DNS query
    /// until cancelled. Blocking; run on its own thread. Throws
    /// UnauthorizedAccessException when not elevated.
    /// </summary>
    public void Watch(Action<DnsQueryEvent> onEvent, CancellationToken token)
    {
        using var session = new TraceEventSession($"WinSight-DNS-{Environment.ProcessId}");
        using var stop = token.Register(() =>
        {
            try
            {
                session.Stop();
            }
            catch (Exception)
            {
                // Session already gone — nothing to do.
            }
        });

        session.EnableProvider(DnsProvider);
        session.Source.Dynamic.All += data =>
        {
            if (data.PayloadByName("QueryName") is string name && name.Length > 0)
            {
                var type = DnsRecordType.Name(AsInt(data.PayloadByName("QueryType")));
                onEvent(new DnsQueryEvent(name, type, data.ProcessID));
            }
        };
        session.Source.Process(); // blocks until the session is stopped
    }

    private static int AsInt(object? value) => value switch
    {
        int i => i,
        uint u => (int)u,
        long l => (int)l,
        ushort s => s,
        string str when int.TryParse(str, out var n) => n,
        _ => 0,
    };
}
