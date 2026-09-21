using System.ComponentModel;
using System.Runtime.InteropServices;

using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

using WinSight.Core;

namespace WinSight.Persistence;

/// <summary>
/// A registry-backed <see cref="IPersistenceChangeSource"/>. It arms
/// <c>RegNotifyChangeKeyValue</c> on a set of autostart keys and raises
/// <see cref="SurfaceChanged"/> whenever any of them changes. It is deliberately a dumb trigger:
/// it reports that a key changed, never which value — the enumerators re-read the truth. This is
/// the thin I/O layer; its runtime behavior is exercised by an HKCU integration test and validated
/// on a real machine, while the monitor's decisions live in the tested pure core.
/// </summary>
/// <remarks>
/// A single background thread waits on all key events plus a cancel event via
/// <see cref="WaitHandle.WaitAny(WaitHandle[])"/>, so the watcher owns exactly one thread. Because
/// <c>WaitAny</c> accepts at most 64 handles, the watcher caps the number of watched keys at 63 and
/// exposes the count it actually armed; the default autostart set is well under that.
///
/// <b>A key that does not exist is watched for its creation.</b> Several autostart keys are absent on
/// an ordinary machine - <c>Policies\Explorer\Run</c> in both hives, <c>RunServices</c>,
/// <c>RunServicesOnce</c> - and a key that could not be opened used to be skipped. Nothing then fired
/// when malware created one and wrote its value into it: the item surfaced only at the next start of
/// the dashboard. The same happened to a watched key that was deleted and recreated, because the
/// re-arm on the deleted handle failed and the watch was quietly dropped while still being counted
/// as armed. Both now fall back to a subkey-creation watch on the nearest ancestor that exists, and
/// move back onto the key itself the moment it appears. A key that exists but cannot be opened is
/// still skipped rather than watched from above, because an ancestor watch sees creation, not the
/// values written inside the key, and counting it would claim coverage that is not there.
///
/// <b>Re-arm first, then notify.</b> A change landing after the re-arm fires again; one landing
/// before it is read by the re-scan the notification triggers. Notifying first left a window in
/// which a change was neither.
/// </remarks>
public sealed class RegistryChangeWatcher :
    IPersistenceChangeSource, IPersistenceWatchCoverage, IPersistenceWatchDiagnostics
{
    private const int MaxWatchedKeys = 63; // WaitAny caps at 64 handles; one slot is the cancel event.
    private const int MaxResolveAttempts = 8;
    private static readonly TimeSpan DefaultRecoveryInterval = TimeSpan.FromSeconds(30);

    [Flags]
    private enum RegNotifyFilter : uint
    {
        Name = 0x00000001,           // REG_NOTIFY_CHANGE_NAME: subkey added or removed.
        LastSet = 0x00000004,        // REG_NOTIFY_CHANGE_LAST_SET: a value was written.
        ThreadAgnostic = 0x10000000, // REG_NOTIFY_THREAD_AGNOSTIC: notify survives the arming thread.
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int RegNotifyChangeKeyValue(
        SafeRegistryHandle hKey,
        [MarshalAs(UnmanagedType.Bool)] bool bWatchSubtree,
        RegNotifyFilter dwNotifyFilter,
        SafeWaitHandle hEvent,
        [MarshalAs(UnmanagedType.Bool)] bool fAsynchronous);

    private sealed class Watch(PersistenceWatchTarget target) : IDisposable
    {
        public PersistenceWatchTarget Target { get; } = target;
        public ManualResetEvent Signal { get; } = new(initialState: false);

        /// <summary>The key currently armed: the target itself, or its nearest existing ancestor.</summary>
        public RegistryKey? Key { get; set; }

        /// <summary>True when <see cref="Key"/> is the target; false while waiting for it to exist.</summary>
        public bool OnTarget { get; set; }

        public bool Armed => Key is not null;

        public void Release()
        {
            Key?.Dispose();
            Key = null;
            OnTarget = false;
        }

        public void Dispose()
        {
            Release();
            Signal.Dispose();
        }
    }

    private readonly IReadOnlyList<PersistenceWatchTarget> _targets;
    private readonly List<Watch> _watches = [];
    private readonly ManualResetEvent _cancel = new(initialState: false);
    private readonly Lock _gate = new();
    private readonly TimeSpan _recoveryInterval;
    private Thread? _thread;
    private bool _started;
    private bool _disposed;
    private int _notificationFailures;
    private int _lostObservations;
    private long _observedEvents;
    private long _recoveryAttempts;
    private long _successfulRecoveries;

    /// <summary>Change signals a subscriber failed to handle.</summary>
    public int NotificationFailures => Volatile.Read(ref _notificationFailures);

    /// <inheritdoc />
    public int LostObservationCount => Volatile.Read(ref _lostObservations);

    public event EventHandler<PersistenceSurfaceChangedEventArgs>? SurfaceChanged;

    public RegistryChangeWatcher(IEnumerable<PersistenceWatchTarget> targets)
        : this(targets, DefaultRecoveryInterval)
    {
    }

    internal RegistryChangeWatcher(
        IEnumerable<PersistenceWatchTarget> targets,
        TimeSpan recoveryInterval)
    {
        ArgumentNullException.ThrowIfNull(targets);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(recoveryInterval, TimeSpan.Zero);
        _targets = RegistryTargets(targets);
        _recoveryInterval = recoveryInterval;
    }

    /// <summary>The registry targets exposed by the given enumerators, flattened and de-duplicated.</summary>
    public static RegistryChangeWatcher FromEnumerators(IEnumerable<IAutostartEnumerator> enumerators)
    {
        ArgumentNullException.ThrowIfNull(enumerators);
        return new RegistryChangeWatcher(enumerators.SelectMany(e => e.WatchTargets));
    }

    /// <summary>Keeps only registry targets, de-duplicating identical hive/view/path/subtree tuples.</summary>
    public static IReadOnlyList<PersistenceWatchTarget> RegistryTargets(
        IEnumerable<PersistenceWatchTarget> targets) =>
        targets
            .Where(t => t.Kind == PersistenceWatchKind.Registry)
            .DistinctBy(t => (t.Hive, t.View, t.Path.ToLowerInvariant(), t.Recursive))
            .ToArray();

    /// <summary>
    /// How many targets are armed - on the key itself, or on its nearest ancestor for the key's
    /// creation. Zero until <see cref="Start"/>; a watch that could not be re-armed stops counting.
    /// </summary>
    public int ArmedKeyCount
    {
        get { lock (_gate) { return _watches.Count(watch => watch.Armed); } }
    }

    /// <summary>
    /// How many armed targets do not exist yet and are watched from their nearest ancestor.
    /// </summary>
    public int AwaitingCreationCount
    {
        get { lock (_gate) { return _watches.Count(watch => watch.Armed && !watch.OnTarget); } }
    }

    /// <inheritdoc />
    /// <remarks>Capped at the same bound Start applies, so the two numbers are comparable.</remarks>
    public int RequestedLocations => Math.Min(_targets.Count, MaxWatchedKeys);

    /// <inheritdoc />
    public int ArmedLocations => ArmedKeyCount;

    /// <inheritdoc />
    public SensorHealthSnapshot SensorHealth
    {
        get
        {
            lock (_gate)
            {
                var active = _watches.Count(watch => watch.Armed);
                var lifecycle = !_started
                    ? SensorLifecycle.NotStarted
                    : _disposed
                        ? SensorLifecycle.Stopped
                        : _targets.Count > 0 && active == 0
                            ? SensorLifecycle.Failed
                            : SensorLifecycle.Running;
                return new SensorHealthSnapshot(
                    "Persistence registry",
                    lifecycle,
                    RequestedLocations,
                    active,
                    Interlocked.Read(ref _observedEvents),
                    Volatile.Read(ref _lostObservations),
                    Interlocked.Read(ref _recoveryAttempts),
                    Interlocked.Read(ref _successfulRecoveries),
                    Volatile.Read(ref _notificationFailures));
            }
        }
    }

    public void Start()
    {
        lock (_gate)
        {
            if (_started || _disposed)
            {
                return;
            }
            _started = true;

            foreach (var target in _targets.Take(MaxWatchedKeys))
            {
                var watch = new Watch(target);
                // Keep an initially unavailable target in the set. It counts as unarmed and the
                // wait thread periodically retries it, so a repaired ACL or newly available hive
                // restores coverage without restarting the dashboard.
                _ = TryArm(watch);
                _watches.Add(watch);
            }

            if (_watches.Count == 0)
            {
                return; // nothing to watch (e.g. empty target set); Start is a no-op.
            }

            _thread = new Thread(WaitLoop)
            {
                IsBackground = true,
                Name = "WinSight.RegistryChangeWatcher",
            };
            _thread.Start();
        }
    }

    /// <summary>
    /// Arms <paramref name="watch"/> on its target, or - when the target does not exist - on the
    /// nearest existing ancestor for the target's creation. False when neither can be armed.
    /// </summary>
    private static bool TryArm(Watch watch)
    {
        watch.Release();
        var target = watch.Target;
        for (var attempt = 0; attempt < MaxResolveAttempts; attempt++)
        {
            var opened = TryOpen(target.Hive, target.View, target.Path, out var denied);
            if (opened is not null)
            {
                if (TryNotify(opened, target.Recursive, RegNotifyFilter.Name | RegNotifyFilter.LastSet, watch.Signal))
                {
                    watch.Key = opened;
                    watch.OnTarget = true;
                    return true;
                }
                // Deleted between the open and the arm, or re-ACL'd: resolve again.
                opened.Dispose();
                continue;
            }
            if (denied)
            {
                return false;
            }

            if (NearestExistingAncestor(target) is not { } ancestor)
            {
                return false;
            }
            if (!TryNotify(ancestor.Key, watchSubtree: false, RegNotifyFilter.Name, watch.Signal))
            {
                ancestor.Key.Dispose();
                return false;
            }
            watch.Key = ancestor.Key;
            watch.OnTarget = false;

            // The next component may have been created between opening the ancestor and arming it,
            // in which case this watch would never fire for it. Resolve again when it now exists.
            var appeared = TryOpen(target.Hive, target.View, ancestor.Next, out var appearedDenied);
            if (appeared is null)
            {
                if (MayRemainOnAncestor(nextComponentExists: false, accessDenied: appearedDenied))
                {
                    return true;
                }
                // The component exists but cannot be opened (or its state cannot be established).
                // An ancestor NAME notification does not cover value writes inside it, so retaining
                // this watch would overstate ArmedLocations while leaving the target blind.
                watch.Release();
                return false;
            }
            appeared.Dispose();
            watch.Release();
        }
        return false;
    }

    /// <summary>
    /// Whether it is truthful to wait on an ancestor. Access denied is never equivalent to absent:
    /// only a positively missing next component can be covered by a parent NAME notification.
    /// </summary>
    internal static bool MayRemainOnAncestor(bool nextComponentExists, bool accessDenied) =>
        !nextComponentExists && !accessDenied;

    private static bool TryNotify(RegistryKey key, bool watchSubtree, RegNotifyFilter filter, ManualResetEvent signal)
    {
        try
        {
            return RegNotifyChangeKeyValue(
                key.Handle,
                watchSubtree,
                filter | RegNotifyFilter.ThreadAgnostic,
                signal.SafeWaitHandle,
                fAsynchronous: true) == 0;
        }
        catch (ObjectDisposedException)
        {
            return false;
        }
    }

    private static RegistryKey? TryOpen(RegistryHive hive, RegistryView view, string path, out bool denied)
    {
        denied = false;
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            return baseKey.OpenSubKey(path, writable: false);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or IOException)
        {
            denied = true;
            return null;
        }
    }

    private readonly record struct Ancestor(RegistryKey Key, string Next);

    /// <summary>
    /// The deepest existing ancestor of the target below the hive root, and the path of the component
    /// under it that does not exist yet. Null when no ancestor can be opened.
    /// </summary>
    private static Ancestor? NearestExistingAncestor(PersistenceWatchTarget target)
    {
        var components = target.Path.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        for (var length = components.Length - 1; length >= 1; length--)
        {
            var path = string.Join('\\', components, 0, length);
            var key = TryOpen(target.Hive, target.View, path, out var denied);
            if (key is not null)
            {
                return new Ancestor(key, string.Join('\\', components, 0, length + 1));
            }
            if (denied)
            {
                return null;
            }
        }
        return null;
    }

    private void WaitLoop()
    {
        // handles[0] is the cancel event; handles[i+1] corresponds to _watches[i]. A watch keeps its
        // event for its whole life - only the key behind it changes - so the array never needs to.
        var handles = new WaitHandle[_watches.Count + 1];
        handles[0] = _cancel;
        for (var i = 0; i < _watches.Count; i++)
        {
            handles[i + 1] = _watches[i].Signal;
        }

        while (true)
        {
            int index;
            try
            {
                index = WaitHandle.WaitAny(handles, _recoveryInterval);
            }
            catch (ObjectDisposedException)
            {
                return; // Dispose did not wait for a slow subscriber and released the handles
            }
            if (index == 0)
            {
                return; // cancelled
            }

            if (index == WaitHandle.WaitTimeout)
            {
                RetryUnarmed();
                continue;
            }

            var watch = _watches[index - 1];
            Interlocked.Increment(ref _observedEvents);
            bool notify;
            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }
                watch.Signal.Reset();
                var wasArmed = watch.Armed;
                var wasOnTarget = watch.OnTarget;
                // Re-arm the same key when it is still there; otherwise resolve again, which falls
                // back to the nearest ancestor for a deleted key and moves onto the key itself once
                // a missing one has been created.
                var rearmed = wasOnTarget && watch.Key is { } key
                    && TryNotify(key, watch.Target.Recursive,
                        RegNotifyFilter.Name | RegNotifyFilter.LastSet, watch.Signal);
                if (!rearmed)
                {
                    Interlocked.Increment(ref _recoveryAttempts);
                    if (TryArm(watch))
                    {
                        Interlocked.Increment(ref _successfulRecoveries);
                    }
                    else if (wasArmed)
                    {
                        Interlocked.Increment(ref _lostObservations);
                    }
                }
                // A normal unrelated ancestor change leaves the watch armed on an ancestor and
                // needs no scan. Target change/creation does; total re-arm failure also does because
                // the signal may have been the target becoming inaccessible.
                notify = wasOnTarget || watch.OnTarget || !watch.Armed;
            }

            if (notify)
            {
                NotifySurface(watch.Target);
            }
        }
    }

    /// <summary>
    /// Periodically retries targets that are currently unarmed. A successful recovery forces one
    /// reconciliation because changes may have happened during the blind interval.
    /// </summary>
    internal void RetryUnarmed()
    {
        List<PersistenceWatchTarget> recovered = [];
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            foreach (var watch in _watches.Where(watch => !watch.Armed))
            {
                Interlocked.Increment(ref _recoveryAttempts);
                if (TryArm(watch))
                {
                    Interlocked.Increment(ref _successfulRecoveries);
                    recovered.Add(watch.Target);
                }
            }
        }
        foreach (var target in recovered)
        {
            NotifySurface(target);
        }
    }

    private void NotifySurface(PersistenceWatchTarget target)
    {
        try
        {
            SurfaceChanged?.Invoke(this, new PersistenceSurfaceChangedEventArgs([target]));
        }
        catch (Exception ex) when (!PersistenceMonitor.IsCatastrophic(ex))
        {
            // A dedicated thread: an escaping subscriber exception ended the process. Counted,
            // and the watch keeps running.
            Interlocked.Increment(ref _notificationFailures);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
        }

        _cancel.Set();
        _thread?.Join(TimeSpan.FromSeconds(2));
        lock (_gate)
        {
            foreach (var watch in _watches)
            {
                watch.Dispose();
            }
        }
        _cancel.Dispose();
    }
}
