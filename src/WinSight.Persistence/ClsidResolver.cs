using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// Resolves a COM CLSID to the on-disk in-process server it loads, so CLSID-referencing
/// autostart surfaces (credential providers, browser helper objects, ...) can surface the
/// actual DLL rather than an opaque GUID. Reads
/// <c>HKLM\SOFTWARE\Classes\CLSID\{clsid}\InprocServer32</c> in the given registry view;
/// returns null when the CLSID has no readable in-process server.
/// </summary>
internal static class ClsidResolver
{
    public static string? ResolveInprocServer(string clsid, RegistryView view)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var server = baseKey.OpenSubKey($@"SOFTWARE\Classes\CLSID\{clsid}\InprocServer32");
            return server?.GetValue(null) is string dll && dll.Trim().Length > 0 ? dll : null;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null;
        }
    }
}
