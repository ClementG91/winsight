using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace WinSight.Core;

/// <summary>
/// Raises an event whenever a registry key's subtree changes, via <c>RegNotifyChangeKeyValue</c>. A
/// thin, reusable trigger: it says that something changed, not what, so the caller re-reads and
/// decides. Used for real-time detection where a poll would add latency (input-filter taps,
/// consent-store activations).
/// </summary>
/// <remarks>
/// The notification is one-shot, so the loop re-arms after each change until disposal. The wait is
/// thread-agnostic and cancellation is a dedicated stop event, so disposal returns promptly.
/// </remarks>
public sealed class RegistryKeyWatcher : IDisposable
{
    private const int RegNotifyChangeName = 0x1;
    private const int RegNotifyChangeLastSet = 0x4;
    private const int RegNotifyThreadAgnostic = 0x10000000;
    private const int Filter = RegNotifyChangeName | RegNotifyChangeLastSet | RegNotifyThreadAgnostic;

    private readonly RegistryHive _hive;
    private readonly string _path;
    private readonly ManualResetEventSlim _stop = new(false);
    private RegistryKey? _baseKey;
    private RegistryKey? _key;
    private Thread? _thread;
    private bool _disposed;
    private int _watching;

    /// <summary>Raised on every observed change to the watched subtree. Never after disposal.</summary>
    public event Action? Changed;

    /// <summary>
    /// True while the notification is armed and the watch loop runs. False before it is first armed,
    /// after disposal, and once the loop has stopped because the notification could not be re-armed
    /// - a silent stop a caller relying on this watch must not mistake for a quiet key.
    /// </summary>
    public bool IsWatching => Volatile.Read(ref _watching) == 1;

    public RegistryKeyWatcher(RegistryHive hive, string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _hive = hive;
        _path = path;
    }

    /// <summary>Begins watching. False when the key cannot be opened (caller keeps polling); true otherwise.</summary>
    public bool Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        try
        {
            _baseKey = RegistryKey.OpenBaseKey(_hive, RegistryView.Registry64);
            _key = _baseKey.OpenSubKey(_path);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                     or UnauthorizedAccessException or IOException)
        {
            // A hive this account may not read (policy-restricted HKLM, for one) is not a failure of
            // the caller: it keeps polling. Throwing here would take down the worker that started us.
            _key = null;
        }
        if (_key is null)
        {
            _baseKey?.Dispose();
            _baseKey = null;
            return false;
        }
        _thread = new Thread(Loop) { IsBackground = true, Name = "WinSight.RegistryKeyWatcher" };
        _thread.Start();
        return true;
    }

    private void Loop()
    {
        using var change = new AutoResetEvent(false);
        var handles = new[] { _stop.WaitHandle, change };
        try
        {
            while (!_stop.IsSet)
            {
                if (RegNotifyChangeKeyValue(_key!.Handle, bWatchSubtree: true, Filter, change.SafeWaitHandle, fAsynchronous: true) != 0)
                {
                    return;
                }
                Volatile.Write(ref _watching, 1);
                if (WaitHandle.WaitAny(handles) == 0)
                {
                    return; // stop signalled
                }
                try
                {
                    Changed?.Invoke();
                }
                catch (Exception ex) when (ex is not (OutOfMemoryException or StackOverflowException))
                {
                    // A faulting subscriber must not blind the watch: re-arm and keep observing.
                }
            }
        }
        finally
        {
            Volatile.Write(ref _watching, 0);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _stop.Set();
        _thread?.Join(TimeSpan.FromSeconds(2));
        _key?.Dispose();
        _baseKey?.Dispose();
        _stop.Dispose();
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int RegNotifyChangeKeyValue(
        SafeRegistryHandle hKey,
        [MarshalAs(UnmanagedType.Bool)] bool bWatchSubtree,
        int dwNotifyFilter,
        SafeWaitHandle hEvent,
        [MarshalAs(UnmanagedType.Bool)] bool fAsynchronous);
}
