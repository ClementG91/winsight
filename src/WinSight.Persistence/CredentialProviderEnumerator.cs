using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// Registered credential providers
/// (<c>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{CLSID}</c>),
/// the COM components the Windows logon/lock UI loads to collect credentials. A rogue
/// provider runs in that trusted context and can capture or replay credentials
/// (MITRE T1556 / credential-access persistence). Each CLSID is resolved to its in-process
/// server DLL so an unsigned or untrusted one stands out.
/// </summary>
public sealed class CredentialProviderEnumerator : IAutostartEnumerator
{
    private const string Path =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers";

    public string Surface => "Credential providers";

    public IEnumerable<RawAutostart> Enumerate()
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var root = baseKey.OpenSubKey(Path);
        if (root is null)
        {
            yield break;
        }
        foreach (var clsid in root.GetSubKeyNames())
        {
            if (ClsidResolver.ResolveInprocServer(clsid, RegistryView.Registry64) is { } dll)
            {
                yield return new RawAutostart(
                    AutostartVector.CredentialProvider, clsid, $"HKLM\\{Path}\\{clsid}", dll);
            }
        }
    }
}
