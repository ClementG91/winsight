using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// Netsh helper DLLs, loaded when netsh.exe runs. A malicious helper registered
/// here executes whenever netsh is invoked; a stealthy persistence spot.
/// </summary>
public sealed class NetshHelperEnumerator : IAutostartEnumerator
{
    public bool CanConfirmAbsence => true;

    private const string Path = @"SOFTWARE\Microsoft\NetSh";

    public string Surface => "Netsh helpers";

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
            if (key is null)
            {
                continue;
            }
            foreach (var name in key.GetValueNames())
            {
                if (key.GetValue(name) is string dll && dll.Trim().Length > 0)
                {
                    // A 32-bit helper is loaded by the 32-bit netsh in SysWOW64.
                    yield return new RawAutostart(
                        AutostartVector.NetshHelper, name, $"HKLM\\{Path} [{view}]", dll,
                        Loader: RawAutostart.LoaderFor(view));
                }
            }
        }
    }
}
