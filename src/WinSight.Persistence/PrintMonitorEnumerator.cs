using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// Print monitors, DLLs loaded by the print spooler service (spoolsv). A rogue
/// monitor Driver DLL runs as SYSTEM at boot; a documented persistence vector.
/// </summary>
public sealed class PrintMonitorEnumerator : IAutostartEnumerator
{
    public bool CanConfirmAbsence => true;

    private const string Path = @"SYSTEM\CurrentControlSet\Control\Print\Monitors";

    public string Surface => "Print monitors";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path, watchSubtree: true),
    };

    public IEnumerable<RawAutostart> Enumerate()
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var root = baseKey.OpenSubKey(Path);
        if (root is null)
        {
            yield break;
        }
        foreach (var monitor in root.GetSubKeyNames())
        {
            using var sub = root.OpenSubKey(monitor);
            if (sub?.GetValue("Driver") is string driver && driver.Trim().Length > 0)
            {
                yield return new RawAutostart(
                    AutostartVector.PrintMonitor, monitor, $"HKLM\\{Path}\\{monitor} [Driver]", driver);
            }
        }
    }
}
