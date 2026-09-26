using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// AppInit_DLLs, DLLs that (when LoadAppInit_DLLs is enabled) are injected into
/// every user-mode process that loads user32.dll. A powerful, oft-abused vector;
/// any entry here is worth surfacing. Covers the 64- and 32-bit views.
/// </summary>
public sealed class AppInitDllsEnumerator : IAutostartEnumerator
{
    public bool CanConfirmAbsence => true;

    private const string Path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
    private static readonly char[] Separators = [',', ' '];

    public string Surface => "AppInit_DLLs";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path),
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry32, Path),
    };

    public IEnumerable<RawAutostart> Enumerate()
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var key = baseKey.OpenSubKey(Path);
            if (key?.GetValue("AppInit_DLLs") is not string raw || raw.Trim().Length == 0)
            {
                continue;
            }
            foreach (var dll in raw.Split(
                         Separators,
                         StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                // The 32-bit list is loaded into every 32-bit process, where System32 is SysWOW64.
                yield return new RawAutostart(
                    AutostartVector.AppInitDll, "AppInit_DLLs", $"HKLM\\{Path} [{view}]", dll,
                    Loader: RawAutostart.LoaderFor(view));
            }
        }
    }
}
