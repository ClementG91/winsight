using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
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
    private CanaryOwnerLease? _ownership;
    private readonly CanaryOwnerLease.Store _owners;
    private static readonly JsonSerializerOptions ManifestOptions = new()
    {
        AllowDuplicateProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true,
        MaxDepth = 16,
    };
    private readonly Lock _gate = new();
    private readonly byte[] _seed;
    private readonly string _manifestPath;
    private readonly TimeSpan _manifestLockWait;

    public CanaryManager(byte[]? seed = null, string? manifestPath = null)
        : this(seed, manifestPath, TimeSpan.FromSeconds(30))
    {
    }

    internal CanaryManager(byte[]? seed, string? manifestPath, TimeSpan manifestLockWait)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(manifestLockWait, TimeSpan.Zero);
        _seed = (seed ?? CanaryIdentity.LoadOrCreateSeed()).ToArray();
        _manifestPath = Path.GetFullPath(manifestPath ?? CanaryIdentity.ManifestPath);
        _owners = new CanaryOwnerLease.Store(_manifestPath);
        _manifestLockWait = manifestLockWait;
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
        if (AutomaticFileAccess.DirectoryExists(downloads)
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
            using var lease = AutomaticFileAccess.TryAcquire(path!);
            if (lease is null || lease.IsDirectory)
            {
                return false;
            }
            var expected = CanaryDocument.For(Path.GetExtension(path!));
            using var stream = lease.OpenRead();
            if (lease.Length != expected.Length)
            {
                return false;
            }
            var actual = new byte[expected.Length];
            stream.ReadExactly(actual);
            return actual.AsSpan().SequenceEqual(expected) && lease.IsCurrent();
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
                    if (_canarySet.Contains(path) && AutomaticFileAccess.FileExists(path))
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
            var expected = ExpectedCanaryPaths(directories, _seed);
            using var gate = ManifestLock.Acquire(_manifestPath, _manifestLockWait);
            var saved = ReadManifest(_manifestPath);
            if (!saved.Usable) { throw new IOException("The canary manifest is unknown or unreadable; preserve it for recovery."); }
            var reserved = saved.Records.Select(record => record.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var candidates = expected.Where(path => !reserved.Contains(path)).ToArray();
            // Upper-bound candidate serialization BEFORE owner or decoy creation. Real IDs cannot
            // exceed these decimal widths; no unsupported partial budget is published as healthy.
            var largest = new CanaryFileIdentity(ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, long.MaxValue);
            var nonce = new string('f', 32);
            var placeholder = new CanaryOwnerProof(127, nonce, largest);
            _ = Encode(saved.Records.Concat(candidates.Select(path => new CanaryFileRecord(path, largest)
            { Owner = nonce, OwnerProof = placeholder })).ToList());
            var hadOwner = _ownership is not null;
            var fresh = new List<CanaryFileRecord>();
            try
            {
                if (candidates.Length > 0) { _ownership ??= _owners.Create(); }
                foreach (var path in candidates)
                {
                    var record = PlantOne(path);
                    if (record is not null) { fresh.Add(record); }
                }
                var merged = saved.Records.Concat(fresh).ToList();
                WriteRecords(_manifestPath, merged, saved.Missing);
                // Monitoring and retry scope only become visible after durable accounting succeeds.
                _records.AddRange(fresh);
                _canaries.AddRange(fresh.Select(record => record.Path));
                _canarySet.UnionWith(fresh.Select(record => record.Path));
                _managedPaths.UnionWith(expected);
                if (_ownership is { } unused && !merged.Any(record => record.OwnerProof == unused.Proof))
                {
                    unused.DeleteUnreferenced();
                    unused.Dispose();
                    _ownership = null;
                }
                return _canaries.ToArray();
            }
            catch
            {
                // Exact rollback of only this new batch; never touch older monitoring authority.
                // This is not a multi-file transaction: failed rollback/crash may need manual recovery.
                foreach (var record in fresh) { _ = CanaryFile.TryRemove(record); }
                if (!hadOwner)
                {
                    _ownership?.Dispose();
                    _ownership = null; // Leave uncertain marker occupancy, never infer publication failed cleanly.
                }
                throw;
            }
        }
    }

    private CanaryFileRecord? PlantOne(string path)
    {
        try
        {
            using var lease = AutomaticFileAccess.TryCreateNewFileLease(path, CanaryDocument.For(Path.GetExtension(path)), false);
            if (lease is null) { return null; }
            var identity = CanaryFile.Identity(lease);
            if (identity is null)
            {
                _ = lease.TryDelete();
                throw new IOException("A created canary has no supported identity.");
            }
            return new CanaryFileRecord(path, identity) { Owner = _ownership!.Proof.Nonce, OwnerProof = _ownership.Proof };
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null; // An unwritable target is an honest coverage gap.
        }
    }

    /// <summary>Ends this owner and attempts conservative cleanup in its exact successfully managed scope.</summary>
    public void Remove()
    {
        lock (_gate)
        {
            try
            {
                if (_managedPaths.Count == 0 && _records.Count == 0) { return; }
                using var gate = ManifestLock.Acquire(_manifestPath, _manifestLockWait);
                var saved = ReadManifest(_manifestPath);
                if (!saved.Usable) { throw new IOException("The canary manifest cannot be safely reconciled."); }
                _ = Sweep(_manifestPath, saved, _managedPaths, _owners, _ownership);
            }
            finally
            {
                _canaries.Clear();
                _canarySet.Clear();
                _records.Clear();
                _ownership?.Dispose();
                _ownership = null;
                // Scope survives for an explicit retry with NEW dead-owner proof, never adoption.
            }
        }
    }

    /// <summary>Models a crash: release lifetime handle without claiming any cleanup succeeded.</summary>
    internal void EndSessionWithoutCleanup()
    {
        lock (_gate)
        {
            _ownership?.Dispose();
            _ownership = null;
        }
    }

    private sealed record ManifestRead(bool Usable, bool Missing, List<CanaryFileRecord> Records);

    private static ManifestRead ReadManifest(string path)
    {
        try
        {
            using var lease = AutomaticFileAccess.TryAcquire(path, out var missing);
            if (lease is null) { return new ManifestRead(missing, missing, []); }
            var bytes = CanaryOwnerLease.ReadBounded(lease, MaximumManifestBytes);
            var saved = JsonSerializer.Deserialize<CanaryManifest>(bytes, ManifestOptions);
            if (saved is not { Version: 2 or 3, Files: not null } || saved.Files.Count > MaximumManifestEntries)
            {
                return new ManifestRead(false, false, []);
            }
            // Validate the entire schema/record set before normalizing or using any individual entry.
            foreach (var record in saved.Files)
            {
                if (record is not { Path: not null, Identity: not null }
                    || !Path.IsPathFullyQualified(record.Path) || !AutomaticFileAccess.IsLocal(record.Path)
                    || record.Identity.CreationTime <= 0
                    || (record.Identity.FileIdLow == 0 && record.Identity.FileIdHigh == 0)
                    || (record.OwnerProof is { } proof && (saved.Version != 3
                        || !CanaryOwnerLease.Store.IsValid(proof) || record.Owner != proof.Nonce)))
                {
                    return new ManifestRead(false, false, []);
                }
            }
            var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var records = new List<CanaryFileRecord>();
            foreach (var record in saved.Files)
            {
                var full = Path.GetFullPath(record.Path);
                if (!paths.Add(full)) { return new ManifestRead(false, false, []); }
                records.Add(record with { Path = full });
            }
            return new ManifestRead(true, false, records);
        }
        catch (Exception ex) when (CanaryOwnerLease.IsExpectedFailure(ex) || ex is JsonException or NotSupportedException)
        {
            return new ManifestRead(false, false, []);
        }
    }

    private static byte[] Encode(List<CanaryFileRecord> records)
    {
        if (records.Count > MaximumManifestEntries) { throw new IOException("Too many canary manifest records."); }
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new CanaryManifest(3, records), ManifestOptions);
        if (bytes.Length > MaximumManifestBytes) { throw new IOException("The canary manifest exceeds its byte budget."); }
        return bytes;
    }

    private static void WriteRecords(string path, List<CanaryFileRecord> records, bool missing)
    {
        if (!AtomicFile.TryWrite(path, Encode(records), replaceExisting: !missing))
        {
            throw new IOException("Canary accounting could not be durably published; preserve its recovery evidence.");
        }
    }

    /// <summary>
    /// Removes only original pristine files with a currently held exact death proof. Legacy v2,
    /// missing/changed markers, unknown schemas and unsupported state authorize no automatic deletion.
    /// </summary>
    public static int RemoveOrphans(IReadOnlyList<string> directories, string? manifestPath = null, byte[]? seed = null)
    {
        ArgumentNullException.ThrowIfNull(directories);
        // Enumerate the actual requested scope before early-return: lifecycle callers serialize this
        // complete startup operation, including its real directory input, against disposal.
        var expected = ExpectedCanaryPaths(directories, seed ?? CanaryIdentity.LoadOrCreateSeed());
        var path = Path.GetFullPath(manifestPath ?? CanaryIdentity.ManifestPath);
        ManifestLock.ValidatePath(path);
        using (var probe = AutomaticFileAccess.TryAcquire(path, out var missing))
        {
            if (probe is null && missing) { return 0; } // Read-only absence never creates a state family.
        }
        using var gate = ManifestLock.Acquire(path, TimeSpan.FromSeconds(30));
        var saved = ReadManifest(path);
        if (!saved.Usable || saved.Missing) { return 0; }
        return Sweep(path, saved, expected, new CanaryOwnerLease.Store(path), own: null);
    }

    private static int Sweep(string path, ManifestRead saved, HashSet<string> expected,
        CanaryOwnerLease.Store owners, CanaryOwnerLease? own)
    {
        var acquired = new List<CanaryOwnerLease>();
        var retained = new List<CanaryFileRecord>(saved.Records);
        var removed = 0;
        try
        {
            foreach (var group in saved.Records.Where(record => record.OwnerProof is not null)
                         .GroupBy(record => record.OwnerProof!))
            {
                var proof = group.Key;
                if (!group.Any(record => IsExpectedCanary(record.Path, expected))) { continue; }
                var authority = own is not null && own.Matches(proof) ? own : owners.TryAcquireDead(proof);
                if (authority is null) { continue; }
                if (!ReferenceEquals(authority, own)) { acquired.Add(authority); }
                foreach (var record in group)
                {
                    if (!IsExpectedCanary(record.Path, expected) || !authority.Matches(proof)) { continue; }
                    var outcome = CanaryFile.TryRemoveOrConfirmAbsent(record);
                    if (outcome != CanaryFile.Removal.Preserved)
                    {
                        retained.Remove(record);
                        if (outcome == CanaryFile.Removal.Removed) { removed++; }
                    }
                }
            }
            if (retained.Count != saved.Records.Count) { WriteRecords(path, retained, saved.Missing); }
            // Every dead handle remains held through publication, including partial-directory sweeps.
            // No marker may be retired while ANY retained record still references the full proof.
            foreach (var authority in acquired.Concat(own is null ? [] : new[] { own }))
            {
                if (!retained.Any(record => record.OwnerProof == authority.Proof)) { authority.DeleteUnreferenced(); }
            }
            return removed;
        }
        finally { foreach (var authority in acquired) { authority.Dispose(); } }
    }

    /// <summary>Short native transaction shared across all Windows sessions; never a lifetime lease.</summary>
    private sealed class ManifestLock : IDisposable
    {
        private readonly AutomaticFileAccess.LocalFileLock _file;
        private ManifestLock(AutomaticFileAccess.LocalFileLock file) => _file = file;

        internal static void ValidatePath(string path)
        {
            var leaf = Path.GetFileName(path);
            if (leaf.Length == 0 || leaf.Length + ".lock".Length > 255 || !AutomaticFileAccess.IsLocal(path))
            {
                throw new IOException("Unsupported canary manifest/sidecar path.");
            }
        }

        internal static ManifestLock Acquire(string path, TimeSpan wait)
        {
            ValidatePath(path);
            var watch = Stopwatch.StartNew();
            try
            {
                while (watch.Elapsed < wait)
                {
                    var file = AutomaticFileAccess.TryAcquireExclusiveLockFile(path + ".lock", out var status);
                    if (file is not null) { return new ManifestLock(file); }
                    if (status != LocalFileLockStatus.Busy)
                    {
                        throw new IOException($"The canary manifest gate is unavailable ({status}).");
                    }
                    var remaining = wait - watch.Elapsed;
                    if (remaining > TimeSpan.Zero)
                    {
                        Thread.Sleep(remaining < TimeSpan.FromMilliseconds(20) ? remaining : TimeSpan.FromMilliseconds(20));
                    }
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
            {
                throw new IOException("The canary manifest gate could not be accessed safely.", ex);
            }
            throw new IOException("Timed out waiting for the canary manifest gate.");
        }
        public void Dispose() => _file.Dispose();
    }

    private static HashSet<string> ExpectedCanaryPaths(
        IReadOnlyList<string> directories, byte[] seed)
    {
        var expected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var enumerated = 0;
        foreach (var directory in directories)
        {
            if (++enumerated > MaximumManifestEntries)
            {
                throw new IOException("Too many requested canary directories.");
            }
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
                    if (expected.Count > MaximumManifestEntries)
                    {
                        throw new IOException("Too many requested canary paths.");
                    }
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
