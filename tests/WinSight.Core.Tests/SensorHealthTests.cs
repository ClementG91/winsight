using Xunit;

namespace WinSight.Core.Tests;

public sealed class SensorHealthTests
{
    [Fact]
    public void FullyArmedRunningSensorWithNoLossIsComplete()
    {
        var health = new SensorHealthSnapshot(
            "test", SensorLifecycle.Running, 2, 2, 10, 0, 0, 0, 0);

        Assert.False(health.CoverageIncomplete);
    }

    [Theory]
    [InlineData(1, 0, 0, 0, (int)SensorLifecycle.Running)]
    [InlineData(1, 1, 1, 0, (int)SensorLifecycle.Running)]
    [InlineData(1, 1, 0, 1, (int)SensorLifecycle.Running)]
    [InlineData(1, 1, 0, 0, (int)SensorLifecycle.Failed)]
    public void EveryKnownCoverageHoleIsIncomplete(
        int requested,
        int active,
        long lost,
        long deliveryFailures,
        int lifecycle)
    {
        var health = new SensorHealthSnapshot(
            "test",
            (SensorLifecycle)lifecycle,
            requested,
            active,
            ObservedEvents: 10,
            LostEvents: lost,
            RecoveryAttempts: 1,
            SuccessfulRecoveries: 1,
            DeliveryFailures: deliveryFailures);

        Assert.True(health.CoverageIncomplete);
    }

    [Fact]
    public void RecoveryDoesNotRewriteHistoricalLossIntoCompleteCoverage()
    {
        var health = new SensorHealthSnapshot(
            "test", SensorLifecycle.Running, 1, 1, 100, 3, 1, 1, 0);

        Assert.True(health.CoverageIncomplete);
    }
}
