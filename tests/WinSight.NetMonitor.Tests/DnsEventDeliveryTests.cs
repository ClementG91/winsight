using WinSight.Core;

using Xunit;

namespace WinSight.NetMonitor.Tests;

public sealed class DnsEventDeliveryTests
{
    private static readonly DnsQueryEvent First = new("one.example", "A", 100);
    private static readonly DnsQueryEvent Second = new("two.example", "AAAA", 200);

    [Fact]
    public void Publish_NeverRunsCallerWork_AndCountsBoundedQueueLoss()
    {
        var delivered = 0;
        var health = new EtwSensorHealthTracker("test");
        var delivery = new DnsEventDelivery(_ => delivered++, health, capacity: 2);

        delivery.Publish(First);
        delivery.Publish(Second);
        delivery.Publish(new DnsQueryEvent("overflow.example", "A", 300));

        Assert.Equal(0, delivered);
        Assert.Equal(3, health.SensorHealth.ObservedEvents);
        Assert.Equal(1, health.SensorHealth.LostEvents);
    }

    [Fact]
    public async Task RunAsync_DeliversInProviderOrder()
    {
        var delivered = new List<DnsQueryEvent>();
        var health = new EtwSensorHealthTracker("test");
        var delivery = new DnsEventDelivery(delivered.Add, health, capacity: 2);
        delivery.Publish(First);
        delivery.Publish(Second);
        delivery.Complete();

        await delivery.RunAsync(CancellationToken.None);

        Assert.Equal([First, Second], delivered);
        Assert.Equal(0, health.SensorHealth.LostEvents);
    }

    [Fact]
    public async Task RunAsync_RecordsAndPropagatesCallerFailure()
    {
        var health = new EtwSensorHealthTracker("test");
        var expected = new InvalidOperationException("consumer failed");
        var delivery = new DnsEventDelivery(_ => throw expected, health, capacity: 1);
        delivery.Publish(First);
        delivery.Complete();

        var actual = await Assert.ThrowsAsync<InvalidOperationException>(
            () => delivery.RunAsync(CancellationToken.None));

        Assert.Same(expected, actual);
        Assert.Equal(1, health.SensorHealth.DeliveryFailures);
    }

    [Fact]
    public void CountAndDiscardPending_ReportsCancellationBacklogAsLoss()
    {
        var health = new EtwSensorHealthTracker("test");
        var delivery = new DnsEventDelivery(_ => { }, health, capacity: 2);
        delivery.Publish(First);
        delivery.Publish(Second);
        delivery.Complete();

        delivery.CountAndDiscardPending();

        Assert.Equal(2, health.SensorHealth.LostEvents);
    }
}
