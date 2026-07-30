using ModelContextProtocol;
using WinSight.Application;
using WinSight.Reporting;

namespace WinSight.Mcp;

/// <summary>
/// Reads the WinSight outbound-firewall service's posture for the MCP surface, one conversation
/// at a time.
/// </summary>
/// <remarks>
/// It does not share <see cref="McpScanService"/>'s gate. That one serialises machine scans that
/// may run for a minute and a half; a posture read is a short IPC exchange, and queueing it behind
/// a running scan would make the cheapest question on the server the slowest to answer.
///
/// It still needs a gate of its own. The service publishes a single pipe instance and serves one
/// exchange at a time, so two concurrent reads from this process would contend for it and could
/// time each other out into a false "unavailable" - which is precisely the answer that must never
/// be produced by accident.
/// </remarks>
public sealed class McpFirewallPostureService : IDisposable
{
    private static readonly TimeSpan QueueTimeout = TimeSpan.FromSeconds(5);

    /// <summary>
    /// A whole-read budget. Each individual IPC call is already bounded by the gateway, but a
    /// fully populated machine pages through policies and pending apps, so the calls add up.
    /// Cancelling is safe here because every command sent is a read.
    /// </summary>
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(30);

    private readonly IFirewallPostureReader _reader;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private int _disposed;

    public McpFirewallPostureService(IFirewallPostureReader reader)
    {
        _reader = reader ?? throw new ArgumentNullException(nameof(reader));
    }

    public async Task<ToolReport> ReadAsync(CancellationToken cancellationToken)
    {
        if (!await _gate.WaitAsync(QueueTimeout, cancellationToken).ConfigureAwait(false))
        {
            throw new McpException("Another firewall posture read is already running. Retry shortly.");
        }

        try
        {
            using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            budget.CancelAfter(ReadTimeout);
            try
            {
                var view = await _reader.GetViewAsync(budget.Token).ConfigureAwait(false);
                return FirewallServiceAdapter.BuildReport(view);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // Deliberately an error rather than a report saying "unavailable". The service not
                // answering in time is not evidence about the machine's firewall, and a caller told
                // "unavailable" would reasonably repeat it to the user as fact.
                throw new McpException("The firewall service did not answer within 30 seconds.");
            }
        }
        finally
        {
            ReleaseGate();
        }
    }

    private void ReleaseGate()
    {
        try
        {
            if (Volatile.Read(ref _disposed) == 0)
            {
                _gate.Release();
            }
        }
        catch (ObjectDisposedException)
        {
            // Host shutdown won the race with a completing read.
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _gate.Dispose();
        }
    }
}
