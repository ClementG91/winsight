using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// SilentProcessExit MonitorProcess hijacks (MITRE T1546.012): when IFEO GlobalFlag
/// enables silent-exit monitoring for a target executable, the MonitorProcess
/// registered here is launched every time that target exits, a quiet companion to
/// the IFEO Debugger hijack. Any MonitorProcess entry is reported.
/// </summary>
public sealed class SilentProcessExitEnumerator : IAutostartEnumerator
{
    private int _unreadable;
    public int UnreadableLocations => _unreadable;
    public bool CanConfirmAbsence => true;

    private const string Path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";

    public string Surface => "SilentProcessExit monitors";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path, watchSubtree: true),
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry32, Path, watchSubtree: true),
    };

    /// <summary>
    /// Both views: SilentProcessExit sits in the same redirected part of the registry as IFEO, and
    /// a monitor registered for a 32-bit target lives in the WOW6432Node twin.
    /// </summary>
    public IEnumerable<RawAutostart> Enumerate()
    {
        _unreadable = 0;
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var root = baseKey.OpenSubKey(Path);
            if (root is null)
            {
                continue;
            }
            foreach (var target in root.GetSubKeyNames())
            {
                RawAutostart? entry = null;
                try
                {
                    using var sub = root.OpenSubKey(target);
                    if (sub?.GetValue("MonitorProcess") is string monitor && monitor.Trim().Length > 0)
                    {
                        entry = new RawAutostart(
                            AutostartVector.SilentProcessExit, target,
                            $"HKLM\\{RegistryViews.Describe(Path, view)}\\{target} [MonitorProcess]", monitor);
                    }
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
                {
                    _unreadable++;
                }
                if (entry is { } e)
                {
                    yield return e;
                }
            }
        }
    }
}
