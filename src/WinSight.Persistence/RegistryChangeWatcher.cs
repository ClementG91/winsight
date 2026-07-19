using System.ComponentModel;
using System.Runtime.InteropServices;

using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

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
/// </remarks>
public sealed class RegistryChangeWatcher : IPersistenceChangeSource
{
    private const int MaxWatchedKeys = 63; // WaitAny caps at 64 handles; one slot is the cancel event.

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

    private sealed class Watch(RegistryKey key, PersistenceWatchTarget target) : IDisposable
    {
        public RegistryKey Key { get; } = key;
        public PersistenceWatchTarget Target { get; } = target;
        public ManualResetEvent Signal { get; } = new(initialState: false);

        public void Dispose()
        {
            Signal.Dispose();
            Key.Dispose();
        }
    }

    private readonly IReadOnlyList<PersistenceWatchTarget> _targets;
    private readonly List<Watch> _watches = [];
    private readonly ManualResetEvent _cancel = new(initialState: false);
    private readonly Lock _gate = new();
    private Thread? _thread;
    private bool _started;
    private bool _disposed;

    public event EventHandler<PersistenceSurfaceChangedEventArgs>? SurfaceChanged;

    public RegistryChangeWatcher(IEnumerable<PersistenceWatchTarget> targets)
    {
        ArgumentNullException.ThrowIfNull(targets);
        _targets = RegistryTargets(targets);
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

    /// <summary>How many keys were successfully opened and armed. Zero until <see cref="Start"/>.</summary>
    public int ArmedKeyCount
    {
        get { lock (_gate) { return _watches.Count; } }
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
                var key = TryOpen(target);
                if (key is null)
                {
                    // A key the current token cannot open for notify is an honest blind spot, not a
                    // crash: skip it. The on-start reconciliation diff still covers that surface.
                    continue;
                }
                _watches.Add(new Watch(key, target));
            }

            if (_watches.Count == 0)
            {
                return; // nothing to watch (e.g. empty target set); Start is a no-op.
            }

            foreach (var watch in _watches)
            {
                Arm(watch);
            }

            _thread = new Thread(WaitLoop)
            {
                IsBackground = true,
                Name = "WinSight.RegistryChangeWatcher",
            };
            _thread.Start();
        }
    }

    private static RegistryKey? TryOpen(PersistenceWatchTarget target)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(target.Hive, target.View);
            return baseKey.OpenSubKey(target.Path, writable: false);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or IOException)
        {
            return null;
        }
    }

    private static void Arm(Watch watch)
    {
        var result = RegNotifyChangeKeyValue(
            watch.Key.Handle,
            watch.Target.Recursive,
            RegNotifyFilter.Name | RegNotifyFilter.LastSet | RegNotifyFilter.ThreadAgnostic,
            watch.Signal.SafeWaitHandle,
            fAsynchronous: true);
        if (result != 0)
        {
            throw new Win32Exception(result);
        }
    }

    private void WaitLoop()
    {
        // handles[0] is the cancel event; handles[i+1] corresponds to _watches[i].
        var handles = new WaitHandle[_watches.Count + 1];
        handles[0] = _cancel;
        for (var i = 0; i < _watches.Count; i++)
        {
            handles[i + 1] = _watches[i].Signal;
        }

        while (true)
        {
            var index = WaitHandle.WaitAny(handles);
            if (index == 0)
            {
                return; // cancelled
            }

            var watch = _watches[index - 1];
            // Reset then re-arm so a change arriving after this point still fires. A change landing
            // between reset and re-arm is caught by the next arming; the monitor's debounced full
            // re-scan absorbs the tiny window.
            watch.Signal.Reset();
            SurfaceChanged?.Invoke(this, new PersistenceSurfaceChangedEventArgs(new[] { watch.Target }));
            try
            {
                Arm(watch);
            }
            catch (Win32Exception)
            {
                // The key became unreadable (deleted, permissions changed). Drop this watch; the
                // remaining keys keep working and the on-start diff still covers the surface.
            }
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
        foreach (var watch in _watches)
        {
            watch.Dispose();
        }
        _cancel.Dispose();
    }
}
