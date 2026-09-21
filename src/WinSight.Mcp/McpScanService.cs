using ModelContextProtocol;
using WinSight.Application;
using WinSight.Reporting;

namespace WinSight.Mcp;

public sealed record McpSecurityOptions(bool AllowSensitiveEvidence)
{
    public static McpSecurityOptions FromEnvironment() => new(
        string.Equals(
            Environment.GetEnvironmentVariable("WINSIGHT_MCP_ALLOW_SENSITIVE"),
            "1",
            StringComparison.Ordinal));
}

public sealed class McpScanService : IDisposable
{
    private static readonly TimeSpan QueueTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan DefaultScanTimeout = TimeSpan.FromSeconds(90);
    private readonly SemaphoreSlim _scanGate = new(1, 1);
    private readonly TimeSpan _scanTimeout;
    private int _stalledScan;
    private int _disposed;

    public McpScanService()
        : this(DefaultScanTimeout)
    {
    }

    /// <param name="scanTimeout">How long a request waits before the scan behind it is cancelled.
    /// Injected so the cancellation is testable without a ninety-second test.</param>
    internal McpScanService(TimeSpan scanTimeout)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(scanTimeout, TimeSpan.Zero);
        _scanTimeout = scanTimeout;
    }

    public Task<IReadOnlyList<ToolReport>> RunAsync(
        string? scanner,
        bool flaggedOnly,
        CancellationToken cancellationToken) =>
        ExecuteAsync(
            scanCancellation => scanner is null
                ? Adapters.RunOverview(
                    flaggedOnly,
                    cancellationToken: scanCancellation,
                    allowNetworkLookups: false)
                : [Adapters.Run(
                    scanner,
                    flaggedOnly,
                    allowNetworkLookups: false,
                    cancellationToken: scanCancellation)],
            cancellationToken);

    /// <summary>
    /// Gathers the per-process drill-down under the same single-scan gate and timeout as a scanner.
    /// </summary>
    /// <remarks>
    /// It shares the gate rather than taking its own because it costs what a scan costs: the pivot
    /// runs a full process list and a full connection sweep, so letting it run beside one would put
    /// two signature-verification passes on the machine at once. Measured on a real desktop at ~11 s
    /// for a live pid and ~4 s for an absent one, comfortably inside the 90-second limit.
    /// </remarks>
    public async Task<ToolReport> RunProcessAsync(int pid, CancellationToken cancellationToken)
    {
        var reports = await ExecuteAsync(
            scanCancellation => [Adapters.ProcessDrillDown(pid, scanCancellation)],
            cancellationToken).ConfigureAwait(false);
        return reports[0];
    }

    /// <summary>
    /// Runs <paramref name="work"/> under the single-scan gate, cancelling it when the request is
    /// cancelled or the timeout expires.
    /// </summary>
    /// <remarks>
    /// <b>The timeout used to stop only the waiting.</b> The work was handed the request's token, so
    /// when the timeout fired the caller got an error while the scan ran on - holding the gate, which
    /// is released only when the scan finishes. One stuck provider then made every later tool call
    /// fail with "another scan is already running" until the server was restarted. The work now
    /// receives a token that the timeout cancels too. Work that ignores cancellation still keeps the
    /// gate until it returns, because two scans at once is the thing the gate exists to prevent.
    /// </remarks>
    internal async Task<IReadOnlyList<ToolReport>> ExecuteAsync(
        Func<CancellationToken, IReadOnlyList<ToolReport>> work,
        CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _stalledScan) != 0)
        {
            throw new McpException(
                "The previous WinSight scan did not stop after cancellation and is still running. "
                + "Retry after the provider returns, or restart the MCP child process.");
        }
        if (!await _scanGate.WaitAsync(QueueTimeout, cancellationToken).ConfigureAwait(false))
        {
            throw new McpException("Another WinSight scan is already running. Retry shortly.");
        }

        var releaseGate = true;
        var scanCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        try
        {
            scanCancellation.CancelAfter(_scanTimeout);
            var scanToken = scanCancellation.Token;
            var scanTask = Task.Run(() => work(scanToken), CancellationToken.None);

            try
            {
                return await scanTask.WaitAsync(_scanTimeout, cancellationToken).ConfigureAwait(false);
            }
            catch when (!scanTask.IsCompleted)
            {
                releaseGate = false;
                Volatile.Write(ref _stalledScan, 1);
                _ = scanTask.ContinueWith(
                    _ =>
                    {
                        Volatile.Write(ref _stalledScan, 0);
                        scanCancellation.Dispose();
                        ReleaseGate();
                    },
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
                throw;
            }
        }
        finally
        {
            if (releaseGate)
            {
                scanCancellation.Dispose();
                ReleaseGate();
            }
        }
    }

    private void ReleaseGate()
    {
        try
        {
            if (Volatile.Read(ref _disposed) == 0)
            {
                _scanGate.Release();
            }
        }
        catch (ObjectDisposedException)
        {
            // Host shutdown won the race with a timed-out scan completion.
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _scanGate.Dispose();
        }
    }
}
