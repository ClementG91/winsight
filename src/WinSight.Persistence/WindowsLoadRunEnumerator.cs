using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// The legacy <c>Load</c> and <c>Run</c> values under
/// <c>...\Windows NT\CurrentVersion\Windows</c>, executed at logon for the machine (HKLM)
/// or the current user (HKCU). An old but still-abused autostart spot, distinct from the
/// AppInit_DLLs value in the same key.
/// </summary>
public sealed class WindowsLoadRunEnumerator : IAutostartEnumerator
{
    private const string Path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";

    // The Load/Run values live under this key in both HKLM and HKCU.
    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path),
        PersistenceWatchTarget.Registry(RegistryHive.CurrentUser, RegistryView.Registry64, Path),
    };
    private static readonly string[] Values = ["Load", "Run"];

    public string Surface => "Windows Load/Run";

    public IEnumerable<RawAutostart> Enumerate()
    {
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(Path);
            if (key is null)
            {
                continue;
            }
            foreach (var value in Values)
            {
                if (key.GetValue(value) is string command && command.Trim().Length > 0)
                {
                    yield return new RawAutostart(
                        AutostartVector.WindowsLoadRun, value, $"{HiveName(hive)}\\{Path} [{value}]", command);
                }
            }
        }
    }

    private static string HiveName(RegistryHive hive) =>
        hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
}
