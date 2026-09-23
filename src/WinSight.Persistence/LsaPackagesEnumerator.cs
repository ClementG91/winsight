using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// LSA Security/Authentication/Notification packages, DLLs loaded into the highly
/// privileged LSASS process. A malicious Security Support Provider or password-filter
/// DLL registered here is a classic, powerful persistence + credential-theft vector.
/// Values are REG_MULTI_SZ module base names (resolved against System32).
/// </summary>
public sealed class LsaPackagesEnumerator : IAutostartEnumerator
{
    public bool CanConfirmAbsence => true;

    private const string Path = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private static readonly string[] Values =
        { "Security Packages", "Authentication Packages", "Notification Packages" };

    public string Surface => "LSA packages";

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
        foreach (var value in Values)
        {
            if (key.GetValue(value) is not string[] packages)
            {
                continue;
            }
            foreach (var raw in packages)
            {
                var pkg = raw.Trim();
                if (pkg.Length == 0 || pkg == "\"\"")
                {
                    continue;
                }
                yield return new RawAutostart(
                    AutostartVector.LsaPackage, pkg, $"HKLM\\{Path} [{value}]", pkg);
            }
        }
    }
}
