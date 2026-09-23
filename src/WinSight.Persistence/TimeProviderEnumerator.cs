using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// W32Time time providers, DLLs loaded by the Windows Time service. A rogue provider
/// DllName runs inside the time service; a documented, low-noise persistence spot.
/// </summary>
public sealed class TimeProviderEnumerator : IAutostartEnumerator
{
    public bool CanConfirmAbsence => true;

    private const string Path = @"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders";

    public string Surface => "Time providers";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path, watchSubtree: true),
    };

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
            if (sub?.GetValue("DllName") is string dll && dll.Trim().Length > 0)
            {
                yield return new RawAutostart(
                    AutostartVector.TimeProvider, provider, $"HKLM\\{Path}\\{provider} [DllName]", dll);
            }
        }
    }
}
