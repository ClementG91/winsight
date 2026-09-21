using System.Threading.Channels;

namespace WinSight.NetMonitor;

/// <summary>
/// Bounded handoff between the DNS ETW callback and caller-owned delivery work. The producer never
/// waits: an overloaded consumer loses a counted event instead of stalling the native trace pump.
/// </summary>
internal sealed class DnsEventDelivery
{
    internal const int DefaultCapacity = 1024;

    private readonly Channel<DnsQueryEvent> _channel;
    private readonly Action<DnsQueryEvent> _onEvent;
    private readonly EtwSensorHealthTracker _health;

    public DnsEventDelivery(
        Action<DnsQueryEvent> onEvent,
        EtwSensorHealthTracker health,
        int capacity = DefaultCapacity)
    {
        ArgumentNullException.ThrowIfNull(onEvent);
        ArgumentNullException.ThrowIfNull(health);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);

        _onEvent = onEvent;
        _health = health;
        _channel = Channel.CreateBounded<DnsQueryEvent>(new BoundedChannelOptions(capacity)
        {
            SingleReader = true,
            SingleWriter = true,
            // TryWrite must report a full queue to the producer; DropWrite reports acceptance even
            // when it discards the new item and would make accurate loss accounting impossible.
            FullMode = BoundedChannelFullMode.Wait,
            AllowSynchronousContinuations = false,
        });
    }

    /// <summary>Called only by the ETW callback. Never blocks and never invokes caller code.</summary>
    public void Publish(DnsQueryEvent dnsEvent)
    {
        ArgumentNullException.ThrowIfNull(dnsEvent);
        _health.Observed();
        if (!_channel.Writer.TryWrite(dnsEvent))
        {
            _health.ApplicationEventsLost();
        }
    }

    /// <summary>Runs caller-owned work on the delivery task, preserving provider order.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        await foreach (var dnsEvent in _channel.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
        {
            try
            {
                _onEvent(dnsEvent);
            }
            catch
            {
                _health.DeliveryFailed();
                throw;
            }
        }
    }

    public void Complete() => _channel.Writer.TryComplete();

    /// <summary>
    /// Counts items left behind after cancellation or a failed consumer. Call only after the
    /// producer is complete and the consumer task has ended.
    /// </summary>
    public void CountAndDiscardPending()
    {
        long discarded = 0;
        while (_channel.Reader.TryRead(out _))
        {
            discarded++;
        }
        if (discarded > 0)
        {
            _health.ApplicationEventsLost(discarded);
        }
    }
}
