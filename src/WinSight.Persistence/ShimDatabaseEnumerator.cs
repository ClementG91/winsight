using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// Installed application-compatibility shim databases
/// (<c>...\AppCompatFlags\InstalledSDB\{guid}</c> → <c>DatabasePath</c>). A custom .sdb can
/// inject code or hook APIs into a target process at load, a stealthy persistence and
/// defense-evasion technique (MITRE T1546.011). The built-in system shims live elsewhere;
/// entries here are third-party installs worth reviewing.
/// </summary>
public sealed class ShimDatabaseEnumerator : IAutostartEnumerator
{
    private const string Path =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB";

    public string Surface => "Application shims (sdb)";

    public IEnumerable<RawAutostart> Enumerate()
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var root = baseKey.OpenSubKey(Path);
        if (root is null)
        {
            yield break;
        }
        foreach (var guid in root.GetSubKeyNames())
        {
            using var sub = root.OpenSubKey(guid);
            if (sub?.GetValue("DatabasePath") is string sdb && sdb.Trim().Length > 0)
            {
                yield return new RawAutostart(
                    AutostartVector.ShimDatabase, guid, $"HKLM\\{Path}\\{guid} [DatabasePath]", sdb);
            }
        }
    }
}
