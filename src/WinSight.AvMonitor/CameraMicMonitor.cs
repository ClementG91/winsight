namespace WinSight.AvMonitor;

/// <summary>A camera/mic transition.</summary>
public enum AvEventKind
{
    Activated,
    Deactivated,
}

/// <summary>An app started or stopped using a capture device.</summary>
public sealed record DeviceEvent(AvEventKind Kind, DeviceUsage Usage);

/// <summary>
/// OverSight-class real-time monitor: watches the CapabilityAccessManager and raises
/// an event the moment an app turns the webcam/mic on or off. The transition detection
/// is a pure, unit-tested diff of two snapshots; the loop polls
/// <see cref="CapabilityAccessReader"/> on an interval (a driver-free approach).
/// RegNotifyChangeKeyValue is the future event-driven optimization.
/// </summary>
public sealed class CameraMicMonitor(ICapabilityAccessReader? reader = null, TimeSpan? interval = null)
{
    private readonly ICapabilityAccessReader _reader = reader ?? new CapabilityAccessReader();
    private readonly TimeSpan _interval = interval ?? TimeSpan.FromSeconds(1);

    /// <summary>
    /// The activation/deactivation events between two snapshots. Pure: an app active
    /// now but not before is Activated; active before but not now is Deactivated.
    /// </summary>
    public static IReadOnlyList<DeviceEvent> Diff(
        IReadOnlyList<DeviceUsage> previous, IReadOnlyList<DeviceUsage> current)
    {
        var before = ActiveMap(previous);
        var after = ActiveMap(current);

        var events = new List<DeviceEvent>();
        foreach (var (key, usage) in after)
        {
            if (!before.ContainsKey(key))
            {
                events.Add(new DeviceEvent(AvEventKind.Activated, usage));
            }
        }
        foreach (var (key, usage) in before)
        {
            if (!after.ContainsKey(key))
            {
                events.Add(new DeviceEvent(AvEventKind.Deactivated, usage));
            }
        }
        return events;
    }

    /// <summary>
    /// Polls until cancelled, invoking <paramref name="onEvent"/> for each transition.
    /// Blocking; run on its own thread/task. The wait is cancellation-aware.
    /// </summary>
    public void Watch(Action<DeviceEvent> onEvent, CancellationToken token)
    {
        var previous = _reader.Read();
        while (!token.IsCancellationRequested)
        {
            if (token.WaitHandle.WaitOne(_interval))
            {
                break; // cancelled
            }
            var current = _reader.Read();
            foreach (var e in Diff(previous, current))
            {
                onEvent(e);
            }
            previous = current;
        }
    }

    // Active devices keyed by (kind, app). Indexer assignment dedupes the same app
    // appearing under both HKCU and HKLM.
    private static Dictionary<string, DeviceUsage> ActiveMap(IEnumerable<DeviceUsage> usages)
    {
        var map = new Dictionary<string, DeviceUsage>();
        foreach (var u in usages)
        {
            if (u.Active)
            {
                map[$"{u.Kind}|{u.App}"] = u;
            }
        }
        return map;
    }
}
