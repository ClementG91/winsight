using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// The screensaver executable (SCRNSAVE.EXE), a .scr is just a PE that Windows runs
/// on idle, so pointing it at a payload is a classic, low-noise persistence trick
/// (MITRE T1546.002). Read per-user from HKCU\Control Panel\Desktop and its Group
/// Policy twin, both of which can force a screensaver on.
/// </summary>
public sealed class ScreensaverEnumerator : IAutostartEnumerator
{
    public bool CanConfirmAbsence => true;

    private const string Value = "SCRNSAVE.EXE";
    private static readonly string[] Paths =
    {
        @"Control Panel\Desktop",
        @"Software\Policies\Microsoft\Windows\Control Panel\Desktop",
    };

    public string Surface => "Screensaver";

    public IEnumerable<RawAutostart> Enumerate()
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
        foreach (var path in Paths)
        {
            using var key = baseKey.OpenSubKey(path);
            if (key?.GetValue(Value) is string scr && scr.Trim().Length > 0)
            {
                yield return new RawAutostart(
                    AutostartVector.Screensaver, Value, $"HKCU\\{path} [{Value}]", scr);
            }
        }
    }
}
