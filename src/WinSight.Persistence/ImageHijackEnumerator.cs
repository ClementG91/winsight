using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// Image File Execution Options "Debugger" hijacks: a Debugger value on a target
/// executable makes Windows launch the debugger INSTEAD of the target, a classic
/// persistence/hijack (e.g. hijacking sethc.exe). Each Debugger entry is reported.
/// </summary>
public sealed class ImageHijackEnumerator : IAutostartEnumerator
{
    public bool CanConfirmAbsence => true;

    private const string Path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

    // Per-executable Debugger / GlobalFlag hijacks live in subkeys under this root.
    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path, watchSubtree: true),
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry32, Path, watchSubtree: true),
    };

    public string Surface => "IFEO debuggers";

    /// <summary>
    /// Both registry views, because IFEO is redirected and the two halves govern different
    /// processes.
    /// </summary>
    /// <remarks>
    /// A WOW64 process reads its execution options through the 32-bit ntdll, which is redirected to
    /// <c>SOFTWARE\WOW6432Node\...\Image File Execution Options</c> - the same reason Microsoft's
    /// own guidance for attaching a debugger to a 32-bit application says to write there. Reading
    /// only the 64-bit view left a Debugger value that hijacks every 32-bit process on the machine
    /// completely invisible, on the surface whose whole purpose is to catch that.
    /// </remarks>
    private int _unreadable;
    private readonly List<string> _unreadableScopes = [];

    public int UnreadableLocations => _unreadable;

    public IReadOnlyCollection<string>? UnreadableScopes => _unreadableScopes;

    public IEnumerable<RawAutostart> Enumerate()
    {
        _unreadable = 0;
        _unreadableScopes.Clear();
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var root = baseKey.OpenSubKey(Path);
            if (root is null)
            {
                continue;
            }
            foreach (var target in root.GetSubKeyNames())
            {
                string? debugger = null;
                try
                {
                    using var sub = root.OpenSubKey(target);
                    debugger = sub?.GetValue("Debugger") as string;
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
                {
                    // One protected executable's options key used to end the whole enumeration, both
                    // views included, hiding every Debugger hijack that sorted after it.
                    _unreadable++;
                    _unreadableScopes.Add($"HKLM\\{RegistryViews.Describe(Path, view)}\\{target}");
                    continue;
                }
                if (debugger is { } value && value.Trim().Length > 0)
                {
                    yield return new RawAutostart(
                        AutostartVector.ImageHijack, target,
                        $"HKLM\\{RegistryViews.Describe(Path, view)}\\{target} [Debugger]", value);
                }
            }
        }
    }
}
