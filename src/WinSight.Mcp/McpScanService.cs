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
    private static readonly TimeSpan ScanTimeout = TimeSpan.FromSeconds(90);
    private readonly SemaphoreSlim _scanGate = new(1, 1);
    private int _disposed;

    public async Task<IReadOnlyList<ToolReport>> RunAsync(
        string? scanner,
        bool flaggedOnly,
        CancellationToken cancellationToken)
    {
        if (!await _scanGate.WaitAsync(QueueTimeout, cancellationToken).ConfigureAwait(false))
        {
            throw new McpException("Another WinSight scan is already running. Retry shortly.");
        }

        var releaseGate = true;
        Task<IReadOnlyList<ToolReport>>? scanTask = null;
        try
        {
            scanTask = Task.Run<IReadOnlyList<ToolReport>>(
                () => scanner is null
                    ? Adapters.RunOverview(
                        flaggedOnly,
                        cancellationToken: cancellationToken,
                        allowNetworkLookups: false)
                    : [Adapters.Run(scanner, flaggedOnly, allowNetworkLookups: false)],
                CancellationToken.None);

            try
            {
                return await scanTask.WaitAsync(ScanTimeout, cancellationToken).ConfigureAwait(false);
            }
            catch when (!scanTask.IsCompleted)
            {
                releaseGate = false;
                _ = scanTask.ContinueWith(
                    _ => ReleaseGate(),
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
