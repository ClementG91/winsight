using WinSight.Mcp;
using WinSight.Reporting;

using Xunit;

namespace WinSight.Mcp.Tests;

/// <summary>
/// Reading the alert journal is not a scan. Behind the single-scan gate, asking what WinSight
/// flagged failed with "another scan is already running" for as long as any scan ran.
/// </summary>
public sealed class McpAlertJournalTests
{
    [Fact]
    public async Task TheJournalIsReadWhileAScanHoldsTheGate()
    {
        using var service = new McpScanService(TimeSpan.FromSeconds(30));
        using var release = new ManualResetEventSlim();
        var scanStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var scan = service.ExecuteAsync(
            token =>
            {
                scanStarted.TrySetResult();
                release.Wait(TimeSpan.FromSeconds(20), token);
                return [];
            },
            CancellationToken.None);
        await scanStarted.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var journal = new ToolReport.Builder("alerts").Build("0 alert(s)");

        try
        {
            var read = await McpScanService.ReadJournalAsync(() => journal, CancellationToken.None)
                .WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Same(journal, Assert.Single(read));
        }
        finally
        {
            release.Set();
            await scan.WaitAsync(TimeSpan.FromSeconds(10));
        }
    }

    [Fact]
    public async Task ACancelledRequestDoesNotReadTheJournal()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        var read = false;

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => McpScanService.ReadJournalAsync(
            () =>
            {
                read = true;
                return new ToolReport.Builder("alerts").Build("never");
            },
            cancellation.Token));

        Assert.False(read);
    }
}
