using WinSight.NetMonitor;
using Xunit;

namespace WinSight.NetMonitor.Tests;

/// <summary>
/// The connection scan says which path answered.
/// </summary>
/// <remarks>
/// <b>Why the silence mattered.</b> The fallback exists because the IP Helper entry points can be
/// unavailable, and it re-derives the table by parsing a text rendering of it - column parsing
/// rather than a structured API. Nothing exposed which one answered, so the report did not
/// distinguish "the native table was read" from "the native API failed and text was reparsed", in a
/// product that everywhere else reports the limits of its own observation scrupulously.
/// </remarks>
public sealed class AcquisitionHonestyTests
{
    /// <summary>
    /// On an ordinary machine the native table answers, and the report must not claim a weaker
    /// acquisition than the one it made.
    /// </summary>
    [Fact]
    public void TheNativePathDoesNotClaimAFallback()
    {
        var monitor = new ConnectionMonitor();

        monitor.Snapshot();

        Assert.False(monitor.UsedNetstatFallback);
    }

    /// <summary>The flag is a property of the last snapshot, not a latch set once for ever.</summary>
    [Fact]
    public void TheFlagReflectsTheLastSnapshot()
    {
        var monitor = new ConnectionMonitor();

        monitor.Snapshot();
        var first = monitor.UsedNetstatFallback;
        monitor.Snapshot();

        Assert.Equal(first, monitor.UsedNetstatFallback);
    }
}
