using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// Browser Helper Objects
/// (<c>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{CLSID}</c>),
/// COM add-ins that Internet Explorer and Windows Explorer load in-process. A classic,
/// still-abused injection/persistence spot (MITRE T1176). Both the 64- and 32-bit registry
/// views are scanned and each CLSID is resolved to its server DLL so an untrusted BHO
/// stands out.
/// </summary>
public sealed class BrowserHelperObjectEnumerator : IAutostartEnumerator
{
    private const string Path =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects";

    // Each BHO is a CLSID subkey, across the 64- and 32-bit views.
    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path, watchSubtree: true),
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry32, Path, watchSubtree: true),
    };

    public string Surface => "Browser helper objects";

    public IEnumerable<RawAutostart> Enumerate()
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var root = baseKey.OpenSubKey(Path);
            if (root is null)
            {
                continue;
            }
            foreach (var clsid in root.GetSubKeyNames())
            {
                if (ClsidResolver.ResolveInprocServer(clsid, view) is { } dll)
                {
                    yield return new RawAutostart(
                        AutostartVector.BrowserHelperObject, clsid, $"HKLM\\{Path}\\{clsid} [{view}]", dll);
                }
            }
        }
    }
}
