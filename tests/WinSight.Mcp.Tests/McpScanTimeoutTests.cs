using ModelContextProtocol;

using WinSight.Mcp;
using WinSight.Reporting;

using Xunit;

namespace WinSight.Mcp.Tests;

/// <summary>
/// The scan timeout cancels the scan, not only the wait for it.
/// </summary>
/// <remarks>
/// The work was handed the request's token, so a timed-out request returned an error while the scan
/// ran on and kept the single-scan gate. One stuck provider then made every later tool call fail with
/// "another scan is already running" until the server was restarted.
/// </remarks>
public sealed class McpScanTimeoutTests
{
    /// <remarks>
    /// The budget applies to both scans, and the second one must have room to run: at 200 ms a CI
    /// runner starting many test collections at once scheduled the trivial second scan too late, and
    /// the test failed with a timeout the product never had. The first scan blocks until cancelled,
    /// so a larger budget changes only how long it waits.
    /// </remarks>
    [Fact]
    public async Task ATimedOutScanIsCancelledAndTheNextScanCanRun()
    {
        using var service = new McpScanService(TimeSpan.FromSeconds(3));
        var observedCancellation = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        await Assert.ThrowsAnyAsync<Exception>(() => service.ExecuteAsync(
            token =>
            {
                // A scan that honours cancellation, as the scanners do between items.
                var cancelled = token.WaitHandle.WaitOne(TimeSpan.FromSeconds(30));
                observedCancellation.TrySetResult(cancelled);
                token.ThrowIfCancellationRequested();
                return [];
            },
            CancellationToken.None));

        Assert.True(await observedCancellation.Task.WaitAsync(TimeSpan.FromSeconds(10)),
            "the timeout never cancelled the scan behind it");

        // The gate is free again: a second scan runs instead of being refused as concurrent.
        var report = new ToolReport.Builder("probe").Build("probe");
        var next = await service.ExecuteAsync(_ => [report], CancellationToken.None)
            .WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Same(report, Assert.Single(next));
    }

    [Fact]
    public async Task ACompletedScanReturnsItsReports()
    {
        using var service = new McpScanService(TimeSpan.FromSeconds(30));
        var report = new ToolReport.Builder("probe").Build("probe");

        var reports = await service.ExecuteAsync(_ => [report], CancellationToken.None);

        Assert.Same(report, Assert.Single(reports));
    }

    [Fact]
    public async Task AProviderThatIgnoresCancellationIsReportedAsStalledWithoutAnotherQueueWait()
    {
        using var service = new McpScanService(TimeSpan.FromMilliseconds(100));
        using var release = new ManualResetEventSlim();

        await Assert.ThrowsAnyAsync<Exception>(() => service.ExecuteAsync(
            scanToken =>
            {
                _ = scanToken; // the test deliberately models a provider that ignores cancellation
                release.Wait(CancellationToken.None);
                return [];
            },
            CancellationToken.None));

        var started = DateTime.UtcNow;
        var error = await Assert.ThrowsAsync<McpException>(() =>
            service.ExecuteAsync(_ => [], CancellationToken.None));
        Assert.Contains("still running", error.Message, StringComparison.OrdinalIgnoreCase);
        // Below the 5-second queue timeout, which is what a wait on the queue would take.
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(4),
            "a known stalled provider made the next request wait on the queue timeout");

        release.Set();
        var report = new ToolReport.Builder("recovered").Build("recovered");
        IReadOnlyList<ToolReport>? recovered = null;
        for (var attempt = 0; attempt < 100 && recovered is null; attempt++)
        {
            try
            {
                recovered = await service.ExecuteAsync(_ => [report], CancellationToken.None);
            }
            catch (Exception ex) when (ex is McpException or TimeoutException)
            {
                // Still stalled, or scheduled after the 100 ms budget on a loaded runner: ask again.
                await Task.Delay(10);
            }
        }
        Assert.Same(report, Assert.Single(Assert.IsAssignableFrom<IReadOnlyList<ToolReport>>(recovered)));
    }
}
