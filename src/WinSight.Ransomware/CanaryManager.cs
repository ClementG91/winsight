using System.Text.Json;
using WinSight.Core;

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
    private readonly List<CanaryFileRecord> _records = [];
    private const int MaximumManifestBytes = 1024 * 1024;
    private const int MaximumManifestEntries = 1024;
    private sealed record CanaryManifest(int Version, IReadOnlyList<CanaryFileRecord> Files);
    private readonly HashSet<string> _canarySet = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _managedPaths = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _sessionId = Guid.NewGuid().ToString("N");
    private Mutex? _ownership;
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
        if (AutomaticFileAccess.IsLocal(downloads)
            && Directory.Exists(downloads)
            && seen.Add(downloads))
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
            if (!AutomaticFileAccess.IsLocal(path!))
            {
                return false;
            }
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

    /// <summary>
    /// How many of this directory's expected decoys this session planted and are still present.
    /// </summary>
    /// <remarks>
    /// A preserved file from an earlier run (edited, replaced, locked or legacy) keeps its name, so
    /// <c>CreateNew</c> refuses to plant there. The directory is still watched, but a watched
    /// directory without its decoys is not protected the way the status badge claims.
    /// </remarks>
    public int PlantedCount(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            return 0;
        }
        lock (_gate)
        {
            var count = 0;
            for (var index = 0; index < CanaryIdentity.PerDirectory; index++)
            {
                try
                {
                    var path = Path.GetFullPath(
                        Path.Combine(directory, CanaryIdentity.FileName(_seed, directory, index)));
                    // Still present: a decoy deleted or renamed after planting trips nothing more.
                    if (_canarySet.Contains(path) && File.Exists(path))
                    {
                        count++;
                    }
                }
                catch (Exception ex) when (ex is ArgumentException or NotSupportedException
                                             or PathTooLongException)
                {
                    return 0;
                }
            }
            return count;
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
            // Held while the session lives: another sweep sees these decoys as owned, not orphaned.
            _ownership ??= new Mutex(initiallyOwned: false, SessionMutexName(_sessionId));
            using var manifest = ManifestLock.Acquire(_manifestPath);
            _managedPaths.UnionWith(ExpectedCanaryPaths(directories, _seed));
            var disk = ReadRecords(_manifestPath);
            RestoreRecords(disk);
            foreach (var directory in directories)
            {
                if (string.IsNullOrWhiteSpace(directory)
                    || !AutomaticFileAccess.IsLocal(directory)
                    || !Directory.Exists(directory))
                {
                    continue;
                }
                for (var index = 0; index < CanaryIdentity.PerDirectory; index++)
                {
                    PlantOne(directory, index);
                }
            }
            WriteRecords(_manifestPath, Merge(disk, _records, removed: []));
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
            CanaryFileIdentity? identity;
            using (var stream = new FileStream(
                       path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                // Matched to the name. Every decoy used to get a workbook, including the ones
                // named .docx: both are OOXML ZIPs so the magic number matched, but the package
                // declared a spreadsheet - the same tell one level in.
                var content = CanaryDocument.For(Path.GetExtension(name));
                stream.Write(content, 0, content.Length);
                stream.Flush();
                identity = CanaryFile.Identity(stream.SafeFileHandle);
            }
            var full = Path.GetFullPath(path);
            if (identity is not null)
            {
                // A previously tracked file can have disappeared before this successful CreateNew.
                _records.RemoveAll(record => record.Path.Equals(full, StringComparison.OrdinalIgnoreCase));
                _records.Add(new CanaryFileRecord(full, identity) { Owner = _sessionId });
            }
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

    /// <summary>Removes original, unmodified decoys; preserves replacements and edits. Best-effort.</summary>
    public void Remove()
    {
        lock (_gate)
        {
            if (_managedPaths.Count == 0 && _records.Count == 0)
            {
                // Never planted: nothing of this session's to remove, and no reason to rewrite (or,
                // as an earlier version did, delete) a manifest holding other sessions' records.
                return;
            }
            using (ManifestLock.Acquire(_manifestPath))
            {
                var disk = ReadRecords(_manifestPath);
                // Only paths this session is responsible for; records kept for other directories wait
                // for a caller that manages those directories.
                var removed = new List<CanaryFileRecord>();
                _records.RemoveAll(record =>
                {
                    var deleted = IsExpectedCanary(record.Path, _managedPaths) && CanaryFile.TryRemove(record);
                    if (deleted)
                    {
                        removed.Add(record);
                    }
                    return deleted;
                });
                // A file can be locked temporarily. Keep its original identity for a later retry;
                // changed/replaced documents will continue to fail the same safe deletion check.
                WriteRecords(_manifestPath, Merge(disk, _records, removed));
            }
            _canaries.Clear();
            _canarySet.Clear();
            // The session is over: what it could not delete is now an orphan for the next sweep.
            _ownership?.Dispose();
            _ownership = null;
        }
    }

    /// <summary>
    /// Releases session ownership without cleaning up, which is what a crash or kill does. Tests use
    /// it to model a previous run in the same process.
    /// </summary>
    internal void EndSessionWithoutCleanup()
    {
        lock (_gate)
        {
            _ownership?.Dispose();
            _ownership = null;
        }
    }

    private void RestoreRecords(List<CanaryFileRecord> disk)
    {
        foreach (var record in disk)
        {
            if (!IsOwnedByLiveSession(record)
                && !_records.Any(existing => existing.Path.Equals(record.Path, StringComparison.OrdinalIgnoreCase)))
            {
                // Keep cleanup authority for a prior original that was temporarily locked, including
                // one in a directory outside this session's set (a removed Downloads folder, a changed
                // OneDrive redirection). Retaining a record never enrolls it in monitoring, and
                // deletion still requires the expected-path check, the recorded identity and pristine
                // content. Records of another live session are left to that session.
                _records.Add(record);
            }
        }
    }

    /// <summary>
    /// The manifest after an operation: this caller's records, plus every other record on disk that
    /// the operation did not delete. Nothing another session wrote is dropped.
    /// </summary>
    private static List<CanaryFileRecord> Merge(
        List<CanaryFileRecord> disk, List<CanaryFileRecord> mine, List<CanaryFileRecord> removed)
    {
        var result = new List<CanaryFileRecord>(mine);
        foreach (var record in disk)
        {
            if (!result.Any(existing => existing.Path.Equals(record.Path, StringComparison.OrdinalIgnoreCase))
                && !removed.Any(gone => gone.Path.Equals(record.Path, StringComparison.OrdinalIgnoreCase)
                    && gone.Identity == record.Identity))
            {
                result.Add(record);
            }
        }
        return result;
    }

    private static List<CanaryFileRecord> ReadRecords(string manifestPath) =>
        ReadManifest(manifestPath)?.Files
            .Where(record => record is { Identity: not null, Path: not null })
            .ToList() ?? [];

    private static CanaryManifest? ReadManifest(string manifest)
    {
        try
        {
            if (!AutomaticFileAccess.IsLocal(manifest))
            {
                return null;
            }
            using var stream = new FileStream(manifest, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length > MaximumManifestBytes)
            {
                return null;
            }
            var bytes = new byte[(int)stream.Length];
            stream.ReadExactly(bytes);
            var saved = JsonSerializer.Deserialize<CanaryManifest>(bytes);
            return saved is { Version: 2, Files: not null } && saved.Files.Count <= MaximumManifestEntries
                ? saved : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                     or System.Security.SecurityException or JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Replaces the manifest atomically: an interrupted write leaves the previous manifest, never a
    /// truncated one that would read as malformed and silently drop every record.
    /// </summary>
    private static void WriteRecords(string manifestPath, List<CanaryFileRecord> records)
    {
        if (records.Count == 0)
        {
            TryDelete(manifestPath);
            return;
        }
        var temp = $"{manifestPath}.{Guid.NewGuid():N}.tmp";
        try
        {
            if (!AutomaticFileAccess.IsLocal(manifestPath))
            {
                return;
            }
            Directory.CreateDirectory(Path.GetDirectoryName(manifestPath)!);
            var json = JsonSerializer.SerializeToUtf8Bytes(new CanaryManifest(2, records));
            if (records.Count <= MaximumManifestEntries && json.Length <= MaximumManifestBytes)
            {
                using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    stream.Write(json);
                    stream.Flush(flushToDisk: true);
                }
                File.Move(temp, manifestPath, overwrite: true);
            }
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            // Without the manifest only cross-run orphan recovery is lost; detection is unaffected.
            TryDelete(temp);
        }
    }

    private static bool TryDelete(string path)
    {
        try
        {
            if (!AutomaticFileAccess.IsLocal(path) || !File.Exists(path))
            {
                return false;
            }
            File.SetAttributes(path, FileAttributes.Normal);
            File.Delete(path);
            return true;
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            // A decoy we cannot delete (already gone, locked) is not fatal.
            return false;
        }
    }

    /// <summary>
    /// Deletes decoys left behind by a run that ended without disposing (a crash, a kill, a reboot).
    /// Best-effort; returns how many were removed.
    /// </summary>
    /// <remarks>
    /// Version 2 records file identity captured at creation. Legacy paths and name patterns cannot
    /// distinguish an original from a replacement, even with identical bytes, and are deliberately
    /// preserved. Such files require manual cleanup after an upgrade. Unknown, malformed or oversized
    /// manifests authorise no deletion. Cleanup is bounded and restricted to configured decoy paths.
    /// Decoys of a session that is still running (another dashboard, or protection started while
    /// this sweep ran) are not orphans and are left alone: deleting them would blind that session and
    /// raise its decoy alert.
    /// </remarks>
    public static int RemoveOrphans(
        IReadOnlyList<string> directories,
        string? manifestPath = null,
        byte[]? seed = null)
    {
        ArgumentNullException.ThrowIfNull(directories);
        var removed = 0;
        var manifest = manifestPath ?? CanaryIdentity.ManifestPath;
        var expected = ExpectedCanaryPaths(directories, seed ?? CanaryIdentity.LoadOrCreateSeed());
        using var gate = ManifestLock.Acquire(manifest);
        if (ReadManifest(manifest) is not { } saved)
        {
            return 0;
        }
        var retained = new List<CanaryFileRecord>();
        foreach (var record in saved.Files)
        {
            if (record is not { Identity: not null, Path: not null })
            {
                continue;
            }
            if (!IsOwnedByLiveSession(record) && IsExpectedCanary(record.Path, expected)
                && CanaryFile.TryRemove(record))
            {
                removed++;
            }
            else
            {
                // Live, locked, modified, or outside the directories this caller manages: preserved,
                // and so is the evidence needed to clean it up safely later.
                retained.Add(record);
            }
        }
        WriteRecords(manifest, retained);
        return removed;
    }

    private static string SessionMutexName(string session) => $@"Local\WinSight.CanarySession.{session}";

    private static bool IsOwnedByLiveSession(CanaryFileRecord record)
    {
        if (record.Owner is not { Length: 32 } owner || !owner.All(char.IsAsciiHexDigit))
        {
            return false;
        }
        // The named mutex exists exactly as long as a process holds a handle to it, so a session
        // that crashed, was killed or ended with the machine no longer owns anything.
        if (Mutex.TryOpenExisting(SessionMutexName(owner), out var mutex))
        {
            mutex.Dispose();
            return true;
        }
        return false;
    }

    /// <summary>Serializes read-modify-write of one manifest across threads and processes.</summary>
    private sealed class ManifestLock : IDisposable
    {
        private static readonly TimeSpan Wait = TimeSpan.FromSeconds(30);
        private readonly Mutex _mutex;
        private readonly bool _held;

        private ManifestLock(Mutex mutex, bool held)
        {
            _mutex = mutex;
            _held = held;
        }

        public static ManifestLock Acquire(string manifestPath)
        {
            var key = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(Path.GetFullPath(manifestPath).ToUpperInvariant())))[..32];
            var mutex = new Mutex(initiallyOwned: false, $@"Local\WinSight.CanaryManifest.{key}");
            bool held;
            try
            {
                held = mutex.WaitOne(Wait);
            }
            catch (AbandonedMutexException)
            {
                held = true; // The previous holder died; the atomic write means the file is whole.
            }
            return new ManifestLock(mutex, held);
        }

        public void Dispose()
        {
            if (_held)
            {
                _mutex.ReleaseMutex();
            }
            _mutex.Dispose();
        }
    }
    private static HashSet<string> ExpectedCanaryPaths(
        IReadOnlyList<string> directories, byte[] seed)
    {
        var expected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var directory in directories)
        {
            if (string.IsNullOrWhiteSpace(directory))
            {
                continue;
            }
            try
            {
                var fullDirectory = Path.GetFullPath(directory);
                if (!AutomaticFileAccess.IsLocal(fullDirectory))
                {
                    continue;
                }
                for (var index = 0; index < CanaryIdentity.PerDirectory; index++)
                {
                    expected.Add(Path.Combine(
                        fullDirectory,
                        CanaryIdentity.FileName(seed, directory, index)));
                }
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException
                                         or PathTooLongException)
            {
                // An invalid protection root authorises no cleanup.
            }
        }
        return expected;
    }

    private static bool IsExpectedCanary(string? path, HashSet<string> expected)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            return false;
        }
        try
        {
            return expected.Contains(Path.GetFullPath(path));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException
                                     or PathTooLongException)
        {
            return false;
        }
    }

}
