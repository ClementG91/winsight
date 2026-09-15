using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// Resolves a COM CLSID to the on-disk server it loads, so CLSID-referencing autostart surfaces
/// (credential providers, browser helper objects, <c>TreatAs</c> redirections, …) can surface the
/// actual binary rather than an opaque GUID.
/// </summary>
/// <remarks>
/// <b>Per-user registrations are consulted first, because that is where the hijack is.</b> COM
/// resolves a class through <c>HKCU\Software\Classes</c> before <c>HKLM\SOFTWARE\Classes</c>, and
/// overriding a system CLSID in the user's own hive - which needs no elevation - is the whole of
/// MITRE T1546.015. Reading only HKLM meant WinSight displayed the signed Microsoft DLL while the
/// attacker's DLL was the one actually being loaded: a confidently wrong answer, which is worse than
/// none.
///
/// <b>Both registry views.</b> A 32-bit host resolves the class through the WOW6432Node twin, so a
/// server registered only there governs every 32-bit process and was previously invisible.
///
/// <b>More than InprocServer32.</b> A class can name its code through an in-process server, an
/// out-of-process one, or by <c>TreatAs</c>, which hands the class over to a different CLSID
/// entirely. Following that redirection is what makes a <c>TreatAs</c> entry resolve to a real file
/// instead of reading as "no resolvable image".
///
/// <b>A denied read is neither an answer nor a reason to abort the surface.</b> A denied HKCU
/// override must not fall through to a machine DLL, and letting the exception escape made one
/// protected CLSID end the enumeration of every later credential provider, BHO or scheduled task.
/// <see cref="TryResolveInprocServer"/> reports the gap so the enumerator counts it and continues.
/// </remarks>
internal static class ClsidResolver
{
    private static readonly string[] ServerKeys =
        ["InprocServer32", "InprocServer", "InprocHandler32", "LocalServer32"];

    // A TreatAs can point at a class that points at another. Real chains are one deep; the bound is
    // there so a loop crafted in the registry cannot spin a scan forever.
    private const int MaxTreatAsDepth = 4;

    internal delegate string? RegistryDefaultValueReader(
        RegistryHive hive, RegistryView view, string clsid, string subKey);

    /// <summary>
    /// Resolved server path, or null when the class names no server. A denied read throws, so a
    /// caller that already counts registry failures around this call keeps doing so.
    /// </summary>
    public static string? ResolveInprocServer(string clsid, RegistryView view) =>
        Resolve(clsid, view, depth: 0, Read);

    /// <summary>
    /// False when a registry read needed for the answer was denied; <paramref name="path"/> is then
    /// null and must be treated as an unreadable location, not as an unregistered class.
    /// </summary>
    internal static bool TryResolveInprocServer(
        string clsid, RegistryView view, out string? path, RegistryDefaultValueReader? read = null)
    {
        try
        {
            path = Resolve(clsid, view, depth: 0, read ?? Read);
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or IOException)
        {
            path = null;
            return false;
        }
    }

    private static string? Resolve(string clsid, RegistryView view, int depth, RegistryDefaultValueReader read)
    {
        if (depth > MaxTreatAsDepth || string.IsNullOrWhiteSpace(clsid))
        {
            return null;
        }

        // HKCU before HKLM, which is the order COM itself resolves in.
        foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        {
            foreach (var server in ServerKeys)
            {
                if (read(hive, view, clsid, server) is { } path)
                {
                    return path;
                }
            }
            if (read(hive, view, clsid, "TreatAs") is { } redirect
                && !redirect.Equals(clsid, StringComparison.OrdinalIgnoreCase))
            {
                return Resolve(redirect, view, depth + 1, read);
            }
        }
        return null;
    }

    private static string? Read(RegistryHive hive, RegistryView view, string clsid, string subKey)
    {
        using var baseKey = RegistryKey.OpenBaseKey(hive, view);
        using var key = baseKey.OpenSubKey($@"SOFTWARE\Classes\CLSID\{clsid}\{subKey}");
        return key?.GetValue(null) is string value && value.Trim().Length > 0 ? value : null;
    }
}
