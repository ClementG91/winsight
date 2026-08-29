namespace WinSight.Ransomware;

/// <summary>
/// Plants and tracks decoy ("canary") files in the directories ransomware sweeps. A decoy has no
/// legitimate reason to be modified, renamed, or deleted, so a single touch is a high-confidence
/// signal. Planting and watching the user's own folders needs no elevation.
/// </summary>
/// <remarks>
/// <b>Four properties a decoy needs, none of which the first version had.</b>
/// <list type="bullet">
/// <item>It must not be recognisable. Names came from the constant <c>WinSightGuard_</c> in a public
/// repository, so skipping every decoy was one <c>StartsWith</c> in the attacker's walk. Names now
/// derive from a machine-local seed — see <see cref="CanaryIdentity"/>.</item>
/// <item>It must be the format it claims. A <c>.xlsx</c> holding one line of ASCII beginning
/// "WinSight ransomware canary" is identifiable from its first four bytes, and several families
/// check a magic number before encrypting. See <see cref="CanaryDocument"/>.</item>
/// <item>It must be visible. Decoys were marked <see cref="FileAttributes.Hidden"/>, which removes
/// them from exactly the enumeration they exist to be caught by, because a good many families skip
/// hidden files deliberately. They are ordinary files now; the UI and the documentation say so,
/// because a security tool putting unexplained files in someone's Documents folder must admit it.</item>
/// <item>There must be more than one, and not all at the end. A single decoy per directory, planted
/// under a name that sorts late, is reached only after the files it was protecting have already been
/// encrypted. Three per directory now span an alphabetical walk.</item>
/// </list>
/// </remarks>
public sealed class CanaryManager
{
    private readonly List<string> _canaries = [];
    private readonly HashSet<string> _canarySet = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _gate = new();
    private readonly byte[] _seed;
    private readonly string _manifestPath;

    public CanaryManager(byte[]? seed = null, string? manifestPath = null)
    {
        _seed = seed ?? CanaryIdentity.LoadOrCreateSeed();
        _manifestPath = manifestPath ?? CanaryIdentity.ManifestPath;
    }

    /// <summary>
    /// The default directories to protect: the user's own document-bearing folders.
    /// </summary>
    /// <remarks>
    /// Three (Documents, Desktop, Pictures) covered a minority of what ransomware sweeps. Downloads,
    /// Videos and Music are equally targeted and equally writable without elevation. These resolve
    /// through <see cref="Environment.GetFolderPath(Environment.SpecialFolder)"/>, so a profile
    /// redirected into OneDrive is followed rather than missed.
    /// </remarks>
    public static IReadOnlyList<string> DefaultDirectories()
    {
        var folders = new[]
        {
            Environment.SpecialFolder.MyDocuments,
            Environment.SpecialFolder.Desktop,
            Environment.SpecialFolder.MyPictures,
            Environment.SpecialFolder.MyVideos,
            Environment.SpecialFolder.MyMusic,
        };
        var directories = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var folder in folders)
        {
            var path = Environment.GetFolderPath(folder);
            if (!string.IsNullOrWhiteSpace(path) && seen.Add(path))
            {
                directories.Add(path);
            }
        }

        // Downloads has no SpecialFolder member. It is one of the most consistently targeted
        // directories, so it is worth resolving by convention rather than being skipped.
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        if (Directory.Exists(downloads) && seen.Add(downloads))
        {
            directories.Add(downloads);
        }
        return directories;
    }

    /// <summary>The decoy files currently planted.</summary>
    public IReadOnlyList<string> Planted
    {
        get { lock (_gate) { return _canaries.ToArray(); } }
    }

    /// <summary>
    /// True when the decoy at <paramref name="path"/> still holds exactly the bytes it was planted
    /// with.
    /// </summary>
    /// <remarks>
    /// <b>The signal this qualifies.</b> A touched decoy is the one thing this product presents as
    /// unambiguous, and it was raised by any <c>Changed</c> notification. The decoy directories
    /// deliberately follow the OneDrive redirection and <c>LastWrite</c> is in the notify filter, so
    /// a placeholder being hydrated or dehydrated - or any synchronisation client rewriting the file
    /// byte for byte - raised the alert the operator is told to trust most.
    ///
    /// A decoy's content is deterministic, so the question has an exact answer: rewritten with the
    /// same bytes is not modified.
    ///
    /// <b>Unreadable counts as modified.</b> A decoy that cannot be read is exactly what encryption
    /// in progress looks like, and this is the one place in the codebase where "I could not look"
    /// must not resolve to silence.
    /// </remarks>
    public bool ContentIsIntact(string? path)
    {
        if (!IsCanary(path))
        {
            return false;
        }
        try
        {
            var expected = CanaryDocument.For(Path.GetExtension(path!));
            using var stream = new FileStream(
                path!, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length != expected.Length)
            {
                return false;
            }
            var actual = new byte[expected.Length];
            stream.ReadExactly(actual);
            return actual.AsSpan().SequenceEqual(expected);
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or EndOfStreamException)
        {
            return false;
        }
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
    /// Plants <see cref="CanaryIdentity.PerDirectory"/> decoys in each existing directory
    /// (best-effort — a directory that does not exist or cannot be written is skipped, not fatal)
    /// and records them so a run that ends abruptly can still be cleaned up. Returns all planted
    /// decoys.
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
                for (var index = 0; index < CanaryIdentity.PerDirectory; index++)
                {
                    PlantOne(directory, index);
                }
            }
            WriteManifest();
            return _canaries.ToArray();
        }
    }

    private void PlantOne(string directory, int index)
    {
        var name = CanaryIdentity.FileName(_seed, directory, index);
        var path = Path.Combine(directory, name);
        try
        {
            // CreateNew, so a real file that happens to collide is never overwritten. A security
            // tool that destroys one of the documents it is protecting has failed completely.
            using (var stream = new FileStream(
                       path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                // Matched to the name. Every decoy used to get a workbook, including the ones
                // named .docx: both are OOXML ZIPs so the magic number matched, but the package
                // declared a spreadsheet - the same tell one level in.
                var content = CanaryDocument.For(Path.GetExtension(name));
                stream.Write(content, 0, content.Length);
            }
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

    /// <summary>Removes every planted decoy. Best-effort and idempotent.</summary>
    public void Remove()
    {
        lock (_gate)
        {
            foreach (var path in _canaries)
            {
                TryDelete(path);
            }
            _canaries.Clear();
            _canarySet.Clear();
            TryDelete(_manifestPath);
        }
    }

    private void WriteManifest()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_manifestPath)!);
            File.WriteAllLines(_manifestPath, _canaries);
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            // Without the manifest only cross-run orphan recovery is lost; detection is unaffected.
        }
    }

    private static void TryDelete(string path)
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

    /// <summary>
    /// Deletes decoys left behind by a run that ended without disposing (a crash, a kill, a reboot).
    /// Best-effort; returns how many were removed.
    /// </summary>
    /// <remarks>
    /// Reads the manifest rather than matching a name pattern, because the names deliberately carry
    /// no pattern any more. The legacy <c>WinSightGuard_*.xlsx</c> glob is still swept so decoys
    /// planted by an earlier version are not stranded in the operator's folders forever.
    /// </remarks>
    public static int RemoveOrphans(IReadOnlyList<string> directories, string? manifestPath = null)
    {
        ArgumentNullException.ThrowIfNull(directories);
        var removed = 0;
        var manifest = manifestPath ?? CanaryIdentity.ManifestPath;

        try
        {
            if (File.Exists(manifest))
            {
                foreach (var path in File.ReadAllLines(manifest))
                {
                    if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
                    {
                        TryDelete(path);
                        removed++;
                    }
                }
                TryDelete(manifest);
            }
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            // Fall through to the legacy sweep; a manifest we cannot read is not a reason to stop.
        }

        foreach (var directory in directories)
        {
            if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
            {
                continue;
            }

            string[] legacy;
            try
            {
                legacy = Directory.GetFiles(directory, CanaryIdentity.LegacyGlob);
            }
            catch (Exception ex) when (ex is IOException
                                         or UnauthorizedAccessException
                                         or System.Security.SecurityException)
            {
                continue;
            }

            foreach (var orphan in legacy)
            {
                TryDelete(orphan);
                removed++;
            }
        }
        return removed;
    }
}
