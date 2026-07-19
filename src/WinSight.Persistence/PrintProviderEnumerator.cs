using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// Print providers (<c>HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\{name}</c> →
/// <c>Name</c>), the DLLs the print spooler service (spoolsv, SYSTEM) loads to service print
/// jobs. A rogue provider DLL runs as SYSTEM; a documented persistence and privilege-
/// escalation vector, distinct from print monitors.
/// </summary>
public sealed class PrintProviderEnumerator : IAutostartEnumerator
{
    private const string Path = @"SYSTEM\CurrentControlSet\Control\Print\Providers";

    // Each print provider is a subkey (with a Driver value) under this root.
    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path, watchSubtree: true),
    };

    public string Surface => "Print providers";

    public IEnumerable<RawAutostart> Enumerate()
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var root = baseKey.OpenSubKey(Path);
        if (root is null)
        {
            yield break;
        }
        foreach (var provider in root.GetSubKeyNames())
        {
            using var sub = root.OpenSubKey(provider);
            if (sub?.GetValue("Name") is string dll && dll.Trim().Length > 0)
            {
                yield return new RawAutostart(
                    AutostartVector.PrintProvider, provider, $"HKLM\\{Path}\\{provider} [Name]", dll);
            }
        }
    }
}
