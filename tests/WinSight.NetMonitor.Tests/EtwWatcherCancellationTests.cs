using WinSight.NetMonitor;
using Xunit;

namespace WinSight.NetMonitor.Tests;

public sealed class EtwWatcherCancellationTests
{
    [Fact]
    public void DnsWatcherDoesNotOpenANativeSessionWhenAlreadyCancelled()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Assert.Throws<OperationCanceledException>(() =>
            new DnsEtwWatcher().Watch(_ => { }, cancellation.Token));
    }

    [Fact]
    public void OutboundWatcherDoesNotOpenANativeSessionWhenAlreadyCancelled()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Assert.Throws<OperationCanceledException>(() =>
            new OutboundConnectionWatcher().Watch(_ => { }, cancellation.Token));
    }
}
