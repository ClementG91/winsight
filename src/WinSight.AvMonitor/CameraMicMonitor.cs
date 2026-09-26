using WinSight.Core;

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
/// is a pure, unit-tested diff of two snapshots; the loop re-reads
/// <see cref="CapabilityAccessReader"/> when the consent store signals a change, and on an
/// interval as the fallback (a driver-free approach).
/// </summary>
/// <remarks>
/// <b>Why the fallback interval depends on the signal.</b> Every poll reads the whole consent store,
/// and at one poll a second an idle watch cost about 1.7% of a core - on a monitor meant to run all
/// day on a laptop. While the change signal confirms that every hive it watches is armed, a missed
/// change is not expected and the poll drops to <c>observedInterval</c>; the moment it cannot
/// confirm that, the loop is back on <c>interval</c>, so latency never depends on a watch that has
/// silently stopped.
/// </remarks>
public sealed class CameraMicMonitor(
    ICapabilityAccessReader? reader = null,
    TimeSpan? interval = null,
    Func<IChangeSignal?>? changeSignalFactory = null,
    TimeSpan? observedInterval = null)
{
    private readonly ICapabilityAccessReader _reader = reader ?? new CapabilityAccessReader();
    private readonly TimeSpan _interval = interval ?? TimeSpan.FromSeconds(1);
    private readonly TimeSpan _observedInterval = observedInterval ?? TimeSpan.FromSeconds(30);

    // When supplied, a fresh change signal is created for each Watch run and disposed with it. Its wake
    // handle lets the loop react to a consent-store change immediately; the interval becomes the
    // fallback, not the latency floor. Null (the default) keeps the pure polling behaviour unchanged.
    private readonly Func<IChangeSignal?>? _changeSignalFactory = changeSignalFactory;

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
    public void Watch(Action<DeviceEvent> onEvent, CancellationToken token,
        Action<AcquisitionSnapshot<DeviceUsage>>? onSnapshot = null)
    {
        // State is kept per observation source - (device, store, app) - and only aggregated per
        // (device, app) to decide transitions. Merging stores first threw away the one fact needed
        // to reason about a partial read: which store an observation came from.
        Dictionary<ObservationKey, DeviceUsage>? known = null;
        // The change signal only removes latency from the poll below. It is created and started
        // defensively so that a failure to observe can never stop the monitoring it accelerates:
        // on any fault the loop simply runs as the pure poll it has always been.
        IChangeSignal? changeSignal = null;
        WaitHandle? wake = null;
        try
        {
            changeSignal = _changeSignalFactory?.Invoke();
            wake = changeSignal?.Start();
        }
        catch (Exception ex) when (ex is not (OutOfMemoryException or StackOverflowException))
        {
            changeSignal?.Dispose();
            changeSignal = null;
            wake = null;
        }
        using var ownedSignal = changeSignal;
        // Wait on cancellation first, then the change signal when present: index 0 is always the token.
        var waitHandles = wake is null ? [token.WaitHandle] : new[] { token.WaitHandle, wake };
        while (!token.IsCancellationRequested)
        {
            var current = ReadSnapshot();
            onSnapshot?.Invoke(current.ToCoverage());
            // Seed the first readable snapshot silently. An entirely failed startup read provides
            // no baseline; wait for some observations or a complete read before establishing one.
            if (known is null)
            {
                if (current.IsComplete || current.Items.Count > 0)
                {
                    known = Index(current.Items);
                }
            }
            else
            {
                var next = Carry(known, current);
                foreach (var e in Transitions(Aggregate(known), Aggregate(next)))
                {
                    onEvent(e);
                }
                known = next;
            }
            // Wake on cancellation (index 0 -> stop), on a consent-store change (re-read at once), or on
            // the interval timing out (the polling fallback). Only cancellation ends the loop.
            if (WaitHandle.WaitAny(waitHandles, NextWait(ownedSignal)) == 0)
            {
                break; // cancelled
            }
        }
    }

    /// <summary>
    /// How long to wait before the next fallback read: the slow interval only while the signal
    /// vouches for every hive it watches, re-checked before each wait.
    /// </summary>
    private TimeSpan NextWait(IChangeSignal? signal)
    {
        bool observing;
        try
        {
            observing = signal?.IsObserving == true;
        }
        catch (Exception ex) when (ex is not (OutOfMemoryException or StackOverflowException))
        {
            observing = false; // a signal that cannot answer is not vouching for anything
        }
        return observing && _observedInterval > _interval ? _observedInterval : _interval;
    }

    /// <summary>
    /// The observations after this read: what was read, plus earlier observations the read could not
    /// have seen. Nothing is inferred about a part of the store that was not read.
    /// </summary>
    private static Dictionary<ObservationKey, DeviceUsage> Carry(
        Dictionary<ObservationKey, DeviceUsage> known, CapabilityAccessSnapshot current)
    {
        var next = Index(current.Items);
        foreach (var (key, previous) in known)
        {
            if (next.TryGetValue(key, out var observed))
            {
                // Without provenance a stopped record cannot rule out the same app capturing in a
                // store this read missed. Keep the earlier active observation; a real restart still
                // shows up through its newer start time.
                if (key.Store is null && !current.IsComplete && previous.Active && !observed.Active)
                {
                    next[key] = previous;
                }
            }
            else if (current.MayHide(key.Kind, key.Store, previous.App, previous.Packaged))
            {
                next[key] = previous;
            }
            // Otherwise the record is gone from a store that was read: no capture there.
        }
        return next;
    }

    private static Dictionary<ObservationKey, DeviceUsage> Index(IEnumerable<DeviceUsage> usages)
    {
        var map = new Dictionary<ObservationKey, DeviceUsage>();
        foreach (var usage in usages)
        {
            var key = new ObservationKey(usage.Kind, usage.Store, usage.App.ToUpperInvariant(), usage.Packaged);
            if (!map.TryGetValue(key, out var existing) || (usage.Active && !existing.Active))
            {
                map[key] = usage;
            }
        }
        return map;
    }

    /// <summary>Per (device, app): active when any store observes it active; latest active start wins.</summary>
    private static Dictionary<string, DeviceUsage> Aggregate(Dictionary<ObservationKey, DeviceUsage> observations)
    {
        var map = new Dictionary<string, DeviceUsage>();
        foreach (var (key, usage) in observations)
        {
            if (!usage.Active)
            {
                continue;
            }
            var app = $"{key.Kind}|{key.App}";
            if (!map.TryGetValue(app, out var existing) || usage.LastStart > existing.LastStart)
            {
                map[app] = usage;
            }
        }
        return map;
    }

    private static List<DeviceEvent> Transitions(
        Dictionary<string, DeviceUsage> before, Dictionary<string, DeviceUsage> after)
    {
        var events = new List<DeviceEvent>();
        foreach (var (key, usage) in after)
        {
            if (before.TryGetValue(key, out var earlier))
            {
                // Still active, but started again since the last poll: stopped and restarted
                // between polls, or during a gap in which the stop itself was not readable.
                if (usage.LastStart > earlier.LastStart)
                {
                    events.Add(new DeviceEvent(AvEventKind.Activated, usage));
                }
            }
            else
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

    private CapabilityAccessSnapshot ReadSnapshot()
    {
        try
        {
            return _reader.ReadWithProvenance();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            // A transient acquisition failure loses coverage, not the worker. Retry on the next
            // cancellation-aware poll; unexpected faults remain visible at the host boundary.
            return new CapabilityAccessSnapshot([], [], ProvenanceKnown: false, UnattributedSources: 4);
        }
    }

    private readonly record struct ObservationKey(DeviceKind Kind, CapabilityStore? Store, string App, bool Packaged);
    private static string Key(DeviceUsage usage) => $"{usage.Kind}|{usage.App}";

    // Active devices keyed by (kind, app). Indexer assignment dedupes the same app
    // appearing under both HKCU and HKLM.
    private static Dictionary<string, DeviceUsage> ActiveMap(IEnumerable<DeviceUsage> usages)
    {
        var map = new Dictionary<string, DeviceUsage>();
        foreach (var u in usages)
        {
            if (u.Active)
            {
                map[Key(u)] = u;
            }
        }
        return map;
    }
}
