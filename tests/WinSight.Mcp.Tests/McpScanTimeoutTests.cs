using System.Diagnostics;

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
    private const string StalledMessage = "The previous WinSight scan did not stop after cancellation and is still running. "
        + "Retry after the provider returns, or restart the MCP child process.";

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
        using var release = new ManualResetEventSlim();
        var observedCancellation = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var exited = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var active = 0;
        Exception? failure = null;
        try
        {
            await Assert.ThrowsAnyAsync<Exception>(() => service.ExecuteAsync(
                token =>
                {
                    Interlocked.Increment(ref active);
                    try
                    {
                        // Cancellation acknowledgement alone is not completion. Hold the provider
                        // until the test has also checked that another scan cannot overlap it.
                        var cancelled = token.WaitHandle.WaitOne(TimeSpan.FromSeconds(30));
                        observedCancellation.TrySetResult(cancelled);
                        release.Wait(CancellationToken.None);
                        token.ThrowIfCancellationRequested();
                        return [];
                    }
                    finally
                    {
                        Interlocked.Decrement(ref active);
                        exited.TrySetResult(true);
                    }
                },
                CancellationToken.None));

            var recovery = Stopwatch.StartNew();
            var budget = TimeSpan.FromSeconds(10);
            Assert.True(await observedCancellation.Task.WaitAsync(Remaining(recovery, budget)),
                "the timeout never cancelled the scan behind it");
            var refusedDispatches = 0;
            var error = await Assert.ThrowsAsync<McpException>(() => ExecuteBoundedAsync(service,
                _ => { Interlocked.Increment(ref refusedDispatches); return []; }, recovery, budget));
            Assert.Equal(StalledMessage, error.Message);
            Assert.Equal(0, Volatile.Read(ref refusedDispatches));
            Assert.Equal(1, Volatile.Read(ref active));

            release.Set();
            var report = new ToolReport.Builder("probe").Build("probe");
            var next = await RecoverOnceAsync(service, report, recovery, budget, () => Volatile.Read(ref active));
            Assert.Same(report, Assert.Single(next));
        }
        catch (Exception ex)
        {
            failure = ex;
            throw;
        }
        finally
        {
            await ReleaseAndJoinAsync(release, exited.Task, failure);
        }
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
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var exited = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var active = 0;
        Exception? failure = null;
        try
        {
            await Assert.ThrowsAnyAsync<Exception>(() => service.ExecuteAsync(
                scanToken =>
                {
                    _ = scanToken; // the test deliberately models a provider that ignores cancellation
                    Interlocked.Increment(ref active);
                    entered.TrySetResult(true);
                    try
                    {
                        release.Wait(CancellationToken.None);
                        return [];
                    }
                    finally
                    {
                        Interlocked.Decrement(ref active);
                        exited.TrySetResult(true);
                    }
                },
                CancellationToken.None));

            var started = DateTime.UtcNow;
            var refusal = Stopwatch.StartNew();
            var refusalBudget = TimeSpan.FromSeconds(4);
            await entered.Task.WaitAsync(Remaining(refusal, refusalBudget));
            var refusedDispatches = 0;
            var error = await Assert.ThrowsAsync<McpException>(() => ExecuteBoundedAsync(service,
                _ => { Interlocked.Increment(ref refusedDispatches); return []; }, refusal, refusalBudget));
            Assert.Contains("still running", error.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(StalledMessage, error.Message);
            Assert.Equal(0, Volatile.Read(ref refusedDispatches));
            Assert.Equal(1, Volatile.Read(ref active));
            // Below the 5-second queue timeout, which is what a wait on the queue would take.
            Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(4),
                "a known stalled provider made the next request wait on the queue timeout");

            release.Set();
            var report = new ToolReport.Builder("recovered").Build("recovered");
            var recovered = await RecoverOnceAsync(service, report, Stopwatch.StartNew(),
                TimeSpan.FromMilliseconds(100 * 10), () => Volatile.Read(ref active));
            Assert.Same(report, Assert.Single(Assert.IsAssignableFrom<IReadOnlyList<ToolReport>>(recovered)));
        }
        catch (Exception ex)
        {
            failure = ex;
            throw;
        }
        finally
        {
            await ReleaseAndJoinAsync(release, exited.Task, failure);
        }
    }

    private static async Task<IReadOnlyList<ToolReport>> RecoverOnceAsync(
        McpScanService service, ToolReport report, Stopwatch clock, TimeSpan budget, Func<int> activeProviders)
    {
        var dispatched = 0;
        while (true)
        {
            try
            {
                var recovered = await ExecuteBoundedAsync(service, _ =>
                {
                    Assert.Equal(0, activeProviders());
                    Assert.Equal(1, Interlocked.Increment(ref dispatched));
                    return [report];
                }, clock, budget);
                Assert.Equal(1, Volatile.Read(ref dispatched));
                return recovered;
            }
            catch (McpException ex) when (ex.Message == StalledMessage && Volatile.Read(ref dispatched) == 0)
            {
                // Poll only the documented refusal before dispatch. A real scan failure, timeout
                // or any other MCP error is terminal, even if it happens on a loaded runner.
                Assert.Equal(0, Volatile.Read(ref dispatched));
                await Task.Delay(10).WaitAsync(Remaining(clock, budget));
            }
        }
    }

    private static async Task<IReadOnlyList<ToolReport>> ExecuteBoundedAsync(
        McpScanService service, Func<CancellationToken, IReadOnlyList<ToolReport>> work,
        Stopwatch clock, TimeSpan budget)
    {
        // Check before ExecuteAsync can queue work. Its internal Task.Run may start after
        // cancellation, so also guard the callback before any simulated scan or assertions.
        var remaining = Remaining(clock, budget);
        using var cancellation = new CancellationTokenSource(remaining);
        var entries = 0;
        var exited = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var attempt = service.ExecuteAsync(token =>
        {
            Interlocked.Increment(ref entries);
            try
            {
                token.ThrowIfCancellationRequested();
                _ = Remaining(clock, budget);
                return work(token);
            }
            finally
            {
                exited.TrySetResult(true);
            }
        }, cancellation.Token);
        try
        {
            var result = await attempt.WaitAsync(remaining);
            Assert.Equal(1, Volatile.Read(ref entries));
            Assert.True(exited.Task.IsCompletedSuccessfully);
            return result;
        }
        catch (Exception primary)
        {
            cancellation.Cancel();
            var cleanup = Stopwatch.StartNew();
            var cleanupBudget = TimeSpan.FromSeconds(10);
            List<Exception> failures = [primary];
            try
            {
                await attempt.WaitAsync(Remaining(cleanup, cleanupBudget));
            }
            catch (Exception observed)
            {
                // Cancellation caused by this teardown is expected. Preserve any different
                // scan exception, or failure to observe the API task within the cleanup bound.
                if (!attempt.IsCompleted || (observed is not OperationCanceledException
                    && !ReferenceEquals(observed, primary)))
                {
                    failures.Add(observed);
                }
            }
            if (Volatile.Read(ref entries) != 0)
            {
                try
                {
                    await exited.Task.WaitAsync(Remaining(cleanup, cleanupBudget));
                }
                catch (Exception observed)
                {
                    failures.Add(observed);
                }
            }
            // entries == 0 does not prove the internal worker will never start. A late
            // callback can only check its cancelled token and signal its private exit TCS.
            if (failures.Count != 1)
            {
                throw new AggregateException("Scan attempt cleanup failed after the original test failure.", failures);
            }
            throw;
        }
    }

    private static TimeSpan Remaining(Stopwatch clock, TimeSpan budget)
    {
        var remaining = budget - clock.Elapsed;
        return remaining > TimeSpan.Zero ? remaining
            : throw new TimeoutException("The provider did not recover within the existing fixture budget.");
    }

    private static async Task ReleaseAndJoinAsync(ManualResetEventSlim release, Task exited, Exception? primary)
    {
        release.Set();
        try
        {
            await exited.WaitAsync(TimeSpan.FromSeconds(10));
        }
        catch (Exception cleanup)
        {
            if (primary is not null)
            {
                throw new AggregateException("Provider cleanup failed after the original test failure.", primary, cleanup);
            }
            throw;
        }
    }
}
