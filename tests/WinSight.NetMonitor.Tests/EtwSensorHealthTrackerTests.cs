using WinSight.Core;

using Xunit;

namespace WinSight.NetMonitor.Tests;

public sealed class EtwSensorHealthTrackerTests
{
    [Fact]
    public void LiveNativeLossIsReadWithoutWaitingForSessionShutdown()
    {
        long nativeLost = 0;
        var tracker = new EtwSensorHealthTracker("test");
        tracker.Running(() => Volatile.Read(ref nativeLost));
        tracker.Observed();

        Volatile.Write(ref nativeLost, 7);
        var health = tracker.SensorHealth;

        Assert.Equal(SensorLifecycle.Running, health.Lifecycle);
        Assert.Equal(1, health.ObservedEvents);
        Assert.Equal(7, health.LostEvents);
        Assert.True(health.CoverageIncomplete);
    }

    [Fact]
    public void AStaleLowerLossSnapshotCannotErasePriorLoss()
    {
        long nativeLost = 8;
        var tracker = new EtwSensorHealthTracker("test");
        tracker.Running(() => Volatile.Read(ref nativeLost));
        Assert.Equal(8, tracker.SensorHealth.LostEvents);

        Volatile.Write(ref nativeLost, 2);

        Assert.Equal(8, tracker.SensorHealth.LostEvents);
    }

    [Fact]
    public void NativeAndApplicationQueueLossAreCombinedWithoutErasingEitherSource()
    {
        var tracker = new EtwSensorHealthTracker("test");
        tracker.Running(static () => 7);
        tracker.ApplicationEventsLost(3);

        Assert.Equal(10, tracker.SensorHealth.LostEvents);
        Assert.True(tracker.SensorHealth.CoverageIncomplete);
    }

    [Fact]
    public void DeliveryFailureAndCleanStopRemainDistinguishable()
    {
        var tracker = new EtwSensorHealthTracker("test");
        tracker.Running(static () => 0);
        tracker.DeliveryFailed();
        tracker.Stopped();

        var health = tracker.SensorHealth;
        Assert.Equal(SensorLifecycle.Stopped, health.Lifecycle);
        Assert.Equal(1, health.DeliveryFailures);
        Assert.True(health.CoverageIncomplete);
    }
}
