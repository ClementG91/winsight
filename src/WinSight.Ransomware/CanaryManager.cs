namespace WinSight.Ransomware;

/// <summary>
/// Plants and tracks decoy ("canary") files in the directories ransomware sweeps. A decoy has no
/// legitimate reason to be modified, renamed, or deleted, so a single touch is a high-confidence
/// signal. Planting and watching the user's own Documents/Desktop/Pictures needs no elevation.
/// </summary>
public sealed class CanaryManager
{
    private const string CanaryContent =
        "WinSight ransomware canary. This hidden decoy exists to detect ransomware; do not modify or delete it.\n";

    private readonly List<string> _canaries = [];
    private readonly HashSet<string> _canarySet = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _gate = new();

    /// <summary>The default directories to protect: the current user's Documents, Desktop, Pictures.</summary>
    public static IReadOnlyList<string> DefaultDirectories() =>
    [
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
    ];

    /// <summary>The decoy files currently planted.</summary>
    public IReadOnlyList<string> Planted
    {
        get { lock (_gate) { return _canaries.ToArray(); } }
    }

    /// <summary>True when <paramref name="path"/> is one of the planted decoys (case-insensitive).</summary>
    public bool IsCanary(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }
        string full;
        try
        {
            full = Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
        lock (_gate)
        {
            return _canarySet.Contains(full);
        }
    }

    /// <summary>
    /// Plants one hidden decoy in each existing directory (best-effort — a directory that does not
    /// exist or cannot be written is skipped, not fatal). Returns all planted decoys.
    /// </summary>
    public IReadOnlyList<string> Plant(IReadOnlyList<string> directories)
    {
        ArgumentNullException.ThrowIfNull(directories);
        lock (_gate)
        {
            foreach (var directory in directories)
            {
                if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
                {
                    continue;
                }
                var path = Path.Combine(directory, CanaryFileName());
                try
                {
                    File.WriteAllText(path, CanaryContent);
                    File.SetAttributes(path, FileAttributes.Hidden);
                    var full = Path.GetFullPath(path);
                    _canaries.Add(full);
                    _canarySet.Add(full);
                }
                catch (Exception ex) when (ex is IOException
                                             or UnauthorizedAccessException
                                             or System.Security.SecurityException)
                {
                    // Best-effort: a directory we cannot write is an honest gap, not a crash.
                }
            }
            return _canaries.ToArray();
        }
    }

    /// <summary>Removes every planted decoy. Best-effort and idempotent.</summary>
    public void Remove()
    {
        lock (_gate)
        {
            foreach (var path in _canaries)
            {
                try
                {
                    if (File.Exists(path))
                    {
                        File.SetAttributes(path, FileAttributes.Normal);
                        File.Delete(path);
                    }
                }
                catch (Exception ex) when (ex is IOException
                                             or UnauthorizedAccessException
                                             or System.Security.SecurityException)
                {
                    // A decoy we cannot delete (already gone, locked) is not fatal.
                }
            }
            _canaries.Clear();
            _canarySet.Clear();
        }
    }

    private const string CanaryPrefix = "WinSightGuard_";
    private const string CanaryExtension = ".xlsx";

    /// <summary>The pattern that identifies a WinSight decoy, used to sweep up orphans.</summary>
    internal const string CanaryGlob = $"{CanaryPrefix}*{CanaryExtension}";

    // A plausible-looking document name so ransomware treats it as a real target, made unique so two
    // runs never collide.
    internal static string CanaryFileName() => $"{CanaryPrefix}{Guid.NewGuid():N}{CanaryExtension}";

    /// <summary>
    /// Deletes decoys left behind by a run that ended without disposing (a crash, a kill). Without
    /// this, a hard stop would litter the user's own folders with hidden files that nothing ever
    /// cleans up. Best-effort; returns how many were removed.
    /// </summary>
    public static int RemoveOrphans(IReadOnlyList<string> directories)
    {
        ArgumentNullException.ThrowIfNull(directories);
        var removed = 0;
        foreach (var directory in directories)
        {
            if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
            {
                continue;
            }

            string[] orphans;
            try
            {
                orphans = Directory.GetFiles(directory, CanaryGlob);
            }
            catch (Exception ex) when (ex is IOException
                                         or UnauthorizedAccessException
                                         or System.Security.SecurityException)
            {
                continue;
            }

            foreach (var orphan in orphans)
            {
                try
                {
                    File.SetAttributes(orphan, FileAttributes.Normal);
                    File.Delete(orphan);
                    removed++;
                }
                catch (Exception ex) when (ex is IOException
                                             or UnauthorizedAccessException
                                             or System.Security.SecurityException)
                {
                    // Leave it; the next run tries again.
                }
            }
        }
        return removed;
    }
}
