using Microsoft.Win32;

using WinSight.Core;

namespace WinSight.InputHooks;

/// <summary>
/// Raises an alert the moment a keyboard or mouse class filter is added or removed - the ReiKey-parity
/// real-time signal that a keylogger has installed an input tap, rather than only finding it on the
/// next scan. It watches the two device-setup class keys for changes, re-reads the filter names, and
/// diffs them against the last observation.
/// </summary>
/// <remarks>
/// User-mode and read-only: a registry change notification plus a registry read, no driver and no
/// elevation. The heavy signature verification stays in <see cref="InputFilterScanner"/>; this watcher
/// only reports which service names appeared or disappeared, so the alert is fast and the full verdict
/// is fetched on demand.
/// </remarks>
public sealed class InputFilterWatcher : IDisposable
{
    private const string KeyboardClass = "{4D36E96B-E325-11CE-BFC1-08002BE10318}";
    private const string MouseClass = "{4D36E96F-E325-11CE-BFC1-08002BE10318}";
    private const string ClassRoot = @"SYSTEM\CurrentControlSet\Control\Class";

    private readonly Func<IReadOnlyList<InputFilterRef>> _read;
    private readonly List<RegistryKeyWatcher> _watchers = [];
    private readonly Lock _gate = new();
    private IReadOnlyList<InputFilterRef> _known = [];
    private bool _disposed;

    /// <summary>Raised with the added/removed filters each time the class keys change.</summary>
    public event Action<IReadOnlyList<InputFilterAlert>>? Changed;

    public InputFilterWatcher(Func<IReadOnlyList<InputFilterRef>>? reader = null) =>
        _read = reader ?? ReadFromRegistry;

    /// <summary>Seeds the baseline and begins watching. False when no class key could be watched.</summary>
    public bool Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _known = _read();
        foreach (var classGuid in new[] { KeyboardClass, MouseClass })
        {
            var watcher = new RegistryKeyWatcher(RegistryHive.LocalMachine, $@"{ClassRoot}\{classGuid}");
            watcher.Changed += OnChanged;
            if (watcher.Start())
            {
                _watchers.Add(watcher);
            }
            else
            {
                watcher.Dispose();
            }
        }
        return _watchers.Count > 0;
    }

    private void OnChanged()
    {
        IReadOnlyList<InputFilterAlert> alerts;
        // Read and diff under the lock (both class-key watchers share this), but never invoke a
        // subscriber while holding it: arbitrary handler code under a lock risks stalls and reentrancy.
        lock (_gate)
        {
            var current = _read();
            alerts = InputFilterDiff.Between(_known, current);
            _known = current;
        }
        if (alerts.Count > 0)
        {
            Changed?.Invoke(alerts);
        }
    }

    /// <summary>Reads the current keyboard/mouse Upper/Lower filter names from the class keys.</summary>
    internal static IReadOnlyList<InputFilterRef> ReadFromRegistry()
    {
        var filters = new List<InputFilterRef>();
        foreach (var (stack, classGuid) in new[] { (InputStack.Keyboard, KeyboardClass), (InputStack.Mouse, MouseClass) })
        {
            foreach (var (position, valueName) in new[] { (FilterPosition.Upper, "UpperFilters"), (FilterPosition.Lower, "LowerFilters") })
            {
                foreach (var name in ReadNames(classGuid, valueName))
                {
                    filters.Add(new InputFilterRef(stack, position, name));
                }
            }
        }
        return filters;
    }

    private static string[] ReadNames(string classGuid, string valueName)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey($@"{ClassRoot}\{classGuid}");
            return key?.GetValue(valueName) is string[] names
                ? names.Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim()).ToArray()
                : [];
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return [];
        }
    }

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
    }
}
