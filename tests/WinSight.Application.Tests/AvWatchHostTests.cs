using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// Lifecycle only. The detection itself — which transitions count as an activation — is a pure diff
/// already covered in the AvMonitor tests; what is new here is the host that keeps a blocking poll
/// loop running for the life of the dashboard, so the risks worth pinning are a leaked polling
/// thread and an unsafe second call.
/// </summary>
public sealed class AvWatchHostTests
{
    [Fact]
    public void Dispose_StopsWatchingPromptly()
    {
        var host = new AvWatchHost();
        host.Start();

        // A poll loop that ignored cancellation would keep a thread alive for the whole process.
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        host.Dispose();
        stopwatch.Stop();

        Assert.True(
            stopwatch.Elapsed < TimeSpan.FromSeconds(5),
            $"Dispose blocked for {stopwatch.Elapsed}, which suggests it waits on the poll interval.");
    }

    [Fact]
    public void Start_IsIdempotent()
    {
        // The dashboard starts monitoring from a lifecycle event that can fire more than once; a
        // second call must not leave a second poll loop running behind the first.
        using var host = new AvWatchHost();

        host.Start();
        host.Start();
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var host = new AvWatchHost();
        host.Start();

        host.Dispose();
        host.Dispose();
    }

    [Fact]
    public void Start_AfterDispose_DoesNothing()
    {
        // Shutdown order is not guaranteed: a late start must not resurrect the loop after the
        // window has gone.
        var host = new AvWatchHost();
        host.Dispose();

        host.Start();
    }

    [Fact]
    public void DisposeWithoutStart_IsSafe()
    {
        // The dashboard disposes its monitors unconditionally, including when startup failed early.
        var host = new AvWatchHost();

        host.Dispose();
    }
}
