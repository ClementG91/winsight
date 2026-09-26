using Microsoft.Diagnostics.Tracing.Session;

using WinSight.Core;

namespace WinSight.NetMonitor;

/// <summary>A live DNS query observed via ETW.</summary>
/// <param name="Name">The queried name.</param>
/// <param name="Type">The DNS record type (A, AAAA, ...).</param>
/// <param name="ProcessId">The process that issued the query.</param>
public sealed record DnsQueryEvent(string Name, string Type, int ProcessId);

/// <summary>
/// Real-time DNS visibility via an ETW session on the Microsoft-Windows-DNS-Client
/// provider, every name a process resolves, as it happens (the DNSMonitor "live"
/// mode, complementing the one-shot cache reader). Requires Administrator (creating an
/// ETW session is privileged); the caller surfaces that. The session is stopped
/// cleanly on cancellation.
/// </summary>
public sealed class DnsEtwWatcher : ISensorHealthSource
{
    private const string DnsProvider = "Microsoft-Windows-DNS-Client";

    /// <summary>
    /// The keyword covering the client's query events, which is the only half of this provider the
    /// watcher reads.
    /// </summary>
    /// <remarks>
    /// Without a mask the provider is enabled for every keyword at Verbose, so the session carries
    /// the whole manifest's worth of events for the handful this watcher looks at - and each one is
    /// decoded and searched by field name in a managed callback before being discarded.
    /// </remarks>
    private const ulong DnsQueryKeyword = 0x1;
    private readonly EtwSensorHealthTracker _health = new("DNS ETW");

    public SensorHealthSnapshot SensorHealth => _health.SensorHealth;

    /// <summary>
    /// Opens the ETW session and invokes <paramref name="onEvent"/> for each DNS query
    /// until cancelled. Blocking; run on its own thread. Throws
    /// UnauthorizedAccessException when not elevated.
    /// </summary>
    public void Watch(Action<DnsQueryEvent> onEvent, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(onEvent);
        token.ThrowIfCancellationRequested();

        TraceEventSession? session = null;
        try
        {
            session = EtwSessionLifecycle.OpenNative(EtwSessionProfile.Dns);
            _health.Running(session);
            WatchSession(session, onEvent, token);
            if (token.IsCancellationRequested)
            {
                _health.Stopped();
            }
            else
            {
                _health.FailedUnexpectedReturn();
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            _health.Stopped();
            throw;
        }
        catch (Exception ex) when (!EtwFailure.IsCatastrophic(ex))
        {
            _health.Failed(ex);
            throw;
        }
        finally
        {
            session?.Dispose();
        }
    }

    private void WatchSession(
        TraceEventSession session,
        Action<DnsQueryEvent> onEvent,
        CancellationToken token)
    {
        var delivery = new DnsEventDelivery(onEvent, _health);
        using var stop = token.Register(() =>
        {
            TryStop(session);
        });
        token.ThrowIfCancellationRequested();

        // The provider was enabled with no level and no keyword mask, which means Verbose and
        // every keyword: the DNS client provider then emits its entire dynamic event set, each one
        // decoded from its manifest and searched by field name. Only the query events are read, so
        // the rest is pure cost on the busiest callback the product runs. Informational level and
        // the query keyword ask for what is actually consumed.
        session.EnableProvider(
            DnsProvider,
            Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational,
            DnsQueryKeyword);
        token.ThrowIfCancellationRequested();
        var consumer = Task.Run(async () =>
            {
                try
                {
                    await delivery.RunAsync(token).ConfigureAwait(false);
                }
                catch
                {
                    // A failed caller must terminate the producer too; otherwise ETW would continue
                    // filling and dropping into a queue that nobody can ever drain.
                    TryStop(session);
                    throw;
                }
            },
            // The delegate must start even when shutdown raced scheduling so it can observe the
            // linked token and take the same cleanup path as an already-running consumer.
            CancellationToken.None);
        try
        {
            session.Source.Dynamic.All += data =>
            {
                if (data.PayloadByName("QueryName") is string name && name.Length > 0)
                {
                    var type = DnsRecordType.Name(AsInt(data.PayloadByName("QueryType")));
                    delivery.Publish(new DnsQueryEvent(name, type, data.ProcessID));
                }
            };
            session.Source.Process(); // blocks until the session is stopped
        }
        finally
        {
            delivery.Complete();
            try
            {
                consumer.GetAwaiter().GetResult();
            }
            finally
            {
                delivery.CountAndDiscardPending();
            }
        }
    }

    private static void TryStop(TraceEventSession session)
    {
        try
        {
            session.Stop();
        }
        catch (Exception)
        {
            // Session already gone, nothing to do.
        }
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
