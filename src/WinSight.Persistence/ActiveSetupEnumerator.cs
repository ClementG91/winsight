using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// Active Setup StubPath commands, run once per user at first logon (and again when
/// a component's version bumps). A quiet, per-user persistence spot. Covers both
/// registry views.
/// </summary>
public sealed class ActiveSetupEnumerator : IAutostartEnumerator
{
    public bool CanConfirmAbsence => true;

    private const string Path = @"SOFTWARE\Microsoft\Active Setup\Installed Components";

    public string Surface => "Active Setup";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path, watchSubtree: true),
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry32, Path, watchSubtree: true),
    };

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
            foreach (var component in root.GetSubKeyNames())
            {
                using var sub = root.OpenSubKey(component);
                if (sub?.GetValue("StubPath") is string stub && stub.Trim().Length > 0)
                {
                    yield return new RawAutostart(
                        AutostartVector.ActiveSetup, component,
                        $"HKLM\\{Path}\\{component} [StubPath, {view}]", stub);
                }
            }
        }
    }
}
