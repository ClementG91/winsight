using Xunit;

namespace WinSight.NetMonitor.Tests;

/// <summary>
/// The resolver-cache query is bounded per result. Synchronous retrieval (ReturnImmediately =
/// false) runs the whole query inside Get(), where no Timeout applies - measured: Get() blocked
/// 27 s under a 1 s Timeout - so a stuck WMI provider hung the scan.
/// </summary>
public sealed class WmiQueryOptionsTests
{
    [Fact]
    public void TheDnsCacheQueryIsSemisynchronousForwardOnlyAndBounded()
    {
        var options = DnsCacheReader.QueryOptions();

        Assert.True(options.ReturnImmediately);
        Assert.False(options.Rewindable);
        Assert.InRange(options.Timeout, TimeSpan.FromMilliseconds(1), TimeSpan.FromSeconds(30));
    }
}
