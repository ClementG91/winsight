using Microsoft.Win32;

using WinSight.Core;

namespace WinSight.AvMonitor;

/// <summary>
/// A wake source for the camera/mic watch loop: something that sets a wait handle the moment the
/// consent store changes, so a poll interval is only the fallback, not the latency floor.
/// </summary>
public interface IChangeSignal : IDisposable
{
    /// <summary>
    /// Begins observing and returns a handle that is set (auto-reset) on each observed change, or null
    /// when nothing can be observed (the loop then relies on polling alone).
    /// </summary>
    WaitHandle? Start();

    /// <summary>
    /// True while every source this signal is meant to watch is confirmed armed, so a missed change
    /// is not expected and the caller may poll rarely. False by default: a signal that cannot vouch
    /// for itself only removes latency, and the caller keeps its fast poll.
    /// </summary>
    bool IsObserving => false;
}

/// <summary>
/// The production <see cref="IChangeSignal"/>: a <see cref="RegistryKeyWatcher"/> over the webcam and
/// microphone consent store in both HKCU and HKLM, collapsed into one auto-reset event. Any activation
/// or deactivation wakes the watch loop immediately instead of waiting for the next poll.
/// </summary>
public sealed class ConsentStoreChangeSignal : IChangeSignal
{
    private const string ConsentStore =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

    private static readonly RegistryHive[] Hives = [RegistryHive.CurrentUser, RegistryHive.LocalMachine];

    private readonly List<RegistryKeyWatcher> _watchers = [];
    private readonly AutoResetEvent _changed = new(false);
    private bool _disposed;

    /// <summary>
    /// Both hives are watched and both notifications are armed. Usage is recorded in either, so one
    /// watched hive is not enough to stop polling the other.
    /// </summary>
    public bool IsObserving =>
        !Volatile.Read(ref _disposed)
        && _watchers.Count == Hives.Length
        && _watchers.TrueForAll(watcher => watcher.IsWatching);

    public WaitHandle? Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        foreach (var hive in Hives)
        {
            RegistryKeyWatcher? watcher = null;
            try
            {
                watcher = new RegistryKeyWatcher(hive, ConsentStore);
                watcher.Changed += OnChanged;
                if (watcher.Start())
                {
                    _watchers.Add(watcher);
                    watcher = null; // owned by the list now
                }
            }
            catch (Exception ex) when (ex is not (OutOfMemoryException or StackOverflowException))
            {
                // This signal is only a latency optimization over polling. It must never be able to
                // stop the watch loop that uses it, whatever a restricted hive throws.
            }
            finally
            {
                watcher?.Dispose(); // HKLM in particular may not be watchable; poll covers it.
            }
        }
        return _watchers.Count > 0 ? _changed : null;
    }

    private void OnChanged() => _changed.Set();

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        foreach (var watcher in _watchers)
        {
            watcher.Dispose();
        }
        _watchers.Clear();
        _changed.Dispose();
    }
}
