using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// AppCertDLLs, DLLs loaded into every process that calls CreateProcess/WinExec and
/// related APIs. A powerful, oft-abused injection/persistence vector (MITRE
/// T1546.009). Values are DLL paths.
/// </summary>
public sealed class AppCertDllsEnumerator : IAutostartEnumerator
{
    public bool CanConfirmAbsence => true;

    private const string Path = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls";

    public string Surface => "AppCertDLLs";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path),
    };

    public IEnumerable<RawAutostart> Enumerate()
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = baseKey.OpenSubKey(Path);
        if (key is null)
        {
            yield break;
        }
        foreach (var name in key.GetValueNames())
        {
            if (key.GetValue(name) is string dll && dll.Trim().Length > 0)
            {
                yield return new RawAutostart(AutostartVector.AppCertDll, name, $"HKLM\\{Path}", dll);
            }
        }
    }
}
