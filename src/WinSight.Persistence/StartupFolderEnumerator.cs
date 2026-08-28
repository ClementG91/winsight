using System.Runtime.InteropServices;

namespace WinSight.Persistence;

/// <summary>
/// The Startup folders (per-user and all-users), anything dropped here runs at
/// logon, a classic malware persistence spot. Shortcuts (.lnk) are resolved to their
/// target executable via WScript.Shell (COM), so the signature check sees the real
/// binary; non-shortcut files are reported as-is. Resolution is best-effort, a .lnk
/// that cannot be resolved falls back to the shortcut path.
/// </summary>
/// <param name="folders">
/// The folders to read, as (directory, label). Defaults to the real per-user and all-users Startup
/// folders; supplied by tests so the "folder exists but will not open" path — the one an attacker
/// creates by re-ACLing a drop point — can actually be exercised.
/// </param>
public sealed class StartupFolderEnumerator(
    IReadOnlyList<(string Dir, string Label)>? folders = null) : IAutostartEnumerator
{
    private readonly IReadOnlyList<(string Dir, string Label)> _folders = folders ?? DefaultFolders();

    public string Surface => "Startup folders";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets =>
        _folders
            .Select(f => PersistenceWatchTarget.FileSystem(f.Dir, includeSubdirectories: false))
            .ToArray();

    private int _unreadable;

    /// <inheritdoc />
    /// <remarks>
    /// One per folder that exists but would not open. A startup folder is a classic drop point, and
    /// an attacker who puts something there can also deny read access to it; without this, that
    /// folder would report as empty and the surface would look clean.
    /// </remarks>
    public int UnreadableLocations => Volatile.Read(ref _unreadable);

    public IEnumerable<RawAutostart> Enumerate()
    {
        Volatile.Write(ref _unreadable, 0);
        foreach (var (dir, label) in _folders)
        {
            foreach (var file in SafeFiles(dir))
            {
                yield return new RawAutostart(
                    AutostartVector.StartupFolder,
                    Path.GetFileName(file),
                    $"{label}: {dir}",
                    ResolveCommand(file));
            }
        }
    }

    /// <summary>
    /// This account's Startup folder, the all-users one, and every other profile's.
    /// </summary>
    /// <remarks>
    /// <b>Why the other profiles matter.</b> <c>SpecialFolder.Startup</c> resolves for the account
    /// running the scan and nobody else, so on a multi-account machine a shortcut dropped in another
    /// user's Startup folder ran at their logon and appeared in no report - and, because the folder
    /// was never opened, nothing counted it as unread either. Elevation made it worse rather than
    /// better: as administrator, the special folder points at the administrator's own profile.
    ///
    /// Reading another profile normally requires elevation. A folder that exists and will not open
    /// is counted as unreadable by <see cref="UnreadableLocations"/>, which is what turns this from
    /// a silent gap into a stated one.
    /// </remarks>
    private static List<(string Dir, string Label)> DefaultFolders()
    {
        var folders = new List<(string Dir, string Label)>
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup), "User startup"),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Common startup"),
        };
        var seen = new HashSet<string>(
            folders.Select(folder => folder.Dir), StringComparer.OrdinalIgnoreCase);

        const string StartupUnderProfile =
            @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup";
        foreach (var sid in UserHiveEnumerator.ProfileSids())
        {
            if (UserHiveEnumerator.ProfileDirectory(sid) is not { Length: > 0 } profile)
            {
                continue;
            }
            var startup = Path.Combine(profile, StartupUnderProfile);
            if (seen.Add(startup))
            {
                var owner = Path.GetFileName(Path.TrimEndingDirectorySeparator(profile));
                folders.Add((startup, $"Startup ({owner})"));
            }
        }
        return folders;
    }

    private static string ResolveCommand(string file)
    {
        if (file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
        {
            var target = ResolveShortcut(file);
            return string.IsNullOrEmpty(target) ? file : target;
        }
        return file;
    }

    // Resolves a .lnk's target executable via WScript.Shell. COM interop can fail in
    // several ways (missing object, binder, access), any failure degrades to null.
    private static string? ResolveShortcut(string lnkPath)
    {
        var type = Type.GetTypeFromProgID("WScript.Shell");
        if (type is null)
        {
            return null;
        }
        object? shell = null;
        try
        {
            shell = Activator.CreateInstance(type);
            dynamic wsh = shell!;
            dynamic shortcut = wsh.CreateShortcut(lnkPath);
            return (string?)shortcut.TargetPath;
        }
        catch (Exception)
        {
            return null;
        }
        finally
        {
            if (shell is not null)
            {
                Marshal.FinalReleaseComObject(shell);
            }
        }
    }

    private string[] SafeFiles(string dir)
    {
        try
        {
            return Directory.Exists(dir) ? Directory.GetFiles(dir) : Array.Empty<string>();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A folder that exists but refuses to be listed is not an empty folder, and the
            // difference is the whole finding: this is where something would be hidden.
            Interlocked.Increment(ref _unreadable);
            return Array.Empty<string>();
        }
    }
}
