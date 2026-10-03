using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using WinSight.Core;

namespace WinSight.Response;

/// <summary>
/// The per-user store of operator decisions (allow/ignore/block) for Guardian, ransomware and
/// camera/microphone. One versioned JSON file, written atomically and serialized across threads and
/// processes by a named mutex, exactly like the decoy manifest.
/// </summary>
/// <remarks>
/// Network policy is not kept here: machine-wide firewall rules live in the service-owned,
/// ACL-protected policy store, because a same-user file cannot be the authority for a machine-wide
/// block. This store governs only same-user suppression and trust decisions, and reading a tampered
/// or malformed file yields no rules rather than a wrong "allow".
/// </remarks>
public sealed class RuleStore
{
    private const int CurrentVersion = 1;
    private const int MaxRules = 8192;
    private const long MaxBytes = 8 * 1024 * 1024;
    private static readonly TimeSpan LockWait = TimeSpan.FromSeconds(30);

    private readonly string _path;
    private readonly Func<DateTimeOffset> _clock;
    private readonly TimeSpan _lockWait;

    public RuleStore(string? path = null, Func<DateTimeOffset>? clock = null)
        : this(path, clock, LockWait)
    {
    }

    internal RuleStore(string? path, Func<DateTimeOffset>? clock, TimeSpan lockWait)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(lockWait, TimeSpan.Zero);
        _path = path ?? DefaultPath();
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _lockWait = lockWait;
    }

    /// <summary>Where the rule store lives, beside WinSight's other per-user state.</summary>
    private static string DefaultPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WinSight", "response-rules.json");

    private sealed record RuleFile(int Version, IReadOnlyList<ResponseRule> Rules);

    /// <summary>The active rules for a scope, expired and reboot-scoped entries already dropped.</summary>
    public IReadOnlyList<ResponseRule> ActiveRules(RuleScopeKind scope)
    {
        var now = _clock();
        return Load()
            .Where(rule => rule.Scope == scope && rule.IsActive(now))
            .ToArray();
    }

    /// <summary>
    /// The first active rule covering a candidate, or null. Used by a monitor to decide whether an
    /// operator already ruled on a detection.
    /// </summary>
    public ResponseRule? Match(
        RuleScopeKind scope, string? item = null, string? imagePath = null,
        string? imageSha256 = null, string? publisher = null)
    {
        var now = _clock();
        foreach (var rule in Load())
        {
            if (rule.IsActive(now) && rule.Matches(scope, item, imagePath, imageSha256, publisher))
            {
                return rule;
            }
        }
        return null;
    }

    /// <summary>
    /// Adds a rule and returns it. Returns null - storing nothing - for a rule with no key (it would
    /// match everything), for a <see cref="RuleDuration.Once"/> decision (never stored by design), for a
    /// duration this store cannot honour, and when the store is full or could not be written.
    /// </summary>
    /// <remarks>
    /// <see cref="RuleDuration.UntilReboot"/> and <see cref="RuleDuration.UntilProcessExit"/> need a
    /// lifecycle hook (a boot-time prune, a process-exit watch) that this store does not own. Accepting
    /// them would silently turn "until reboot" into "forever", so they are refused instead.
    /// </remarks>
    public ResponseRule? Add(ResponseRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (!rule.HasKey || rule.Duration is RuleDuration.Once or RuleDuration.UntilReboot
                or RuleDuration.UntilProcessExit)
        {
            return null;
        }
        try
        {
            using var gate = StoreLock.Acquire(_path, _lockWait);
            if (!TryLoadLocked(out var loaded))
            {
                return null;
            }
            var rules = loaded.ToList();
            if (rules.Count >= MaxRules)
            {
                return null;
            }
            rules.RemoveAll(existing => existing.Id == rule.Id);
            rules.Add(rule);
            return Save(rules) ? rule : null;
        }
        catch (Exception ex) when (IsStoreUnavailable(ex))
        {
            return null;
        }
    }

    /// <summary>Removes the rule with this id. True when one was removed and the store was written.</summary>
    public bool Remove(Guid id) => RemoveWithOutcome(id) == ResponseOutcome.Succeeded;

    /// <summary>
    /// Removes a rule durably, distinguishing an absent id from unreadable or unwritable storage.
    /// An unavailable store is never evidence that the rule was absent or revoked.
    /// </summary>
    public ResponseOutcome RemoveWithOutcome(Guid id)
    {
        try
        {
            using var gate = StoreLock.Acquire(_path, _lockWait);
            if (!TryLoadLocked(out var loaded))
            {
                return ResponseOutcome.Failed;
            }
            var rules = loaded.ToList();
            if (rules.RemoveAll(rule => rule.Id == id) == 0)
            {
                return ResponseOutcome.TargetNotFound;
            }
            return Save(rules) ? ResponseOutcome.Succeeded : ResponseOutcome.Failed;
        }
        catch (Exception ex) when (IsStoreUnavailable(ex))
        {
            return ResponseOutcome.Failed;
        }
    }

    /// <summary>
    /// Reads the rules. An unavailable store reads as "no rules", which fails open: a monitor that
    /// cannot read its rules alerts rather than silently suppressing. This path must never throw,
    /// because monitors consult it on every detection.
    /// </summary>
    private ResponseRule[] Load()
    {
        try
        {
            using var gate = StoreLock.Acquire(_path, _lockWait);
            return TryLoadLocked(out var rules) ? rules : [];
        }
        catch (Exception ex) when (IsStoreUnavailable(ex))
        {
            return [];
        }
    }

    /// <summary>
    /// Failures of the environment rather than of the caller: an unusable path, or a store lock that
    /// cannot be created or opened (a same-named object squatted with another ACL, for one).
    /// </summary>
    private static bool IsStoreUnavailable(Exception ex) =>
        ex is IOException or UnauthorizedAccessException or System.Security.SecurityException
            or ArgumentException or NotSupportedException or WaitHandleCannotBeOpenedException;

    private bool TryLoadLocked(out ResponseRule[] rules)
    {
        rules = [];
        try
        {
            using var lease = AutomaticFileAccess.TryAcquire(_path);
            if (lease is null)
            {
                // The local preflight distinguishes a missing file from inaccessible/reparse
                // storage without resolving a network path. Only absence is a valid empty store.
                return AutomaticFileAccess.IsLocal(_path);
            }
            if (lease.IsDirectory || lease.Length > MaxBytes)
            {
                return false;
            }
            using var stream = lease.OpenRead();
            var bytes = new byte[(int)lease.Length];
            stream.ReadExactly(bytes);
            if (!lease.IsCurrent())
            {
                return false;
            }
            var file = JsonSerializer.Deserialize<RuleFile>(bytes);
            if (file is not { Version: CurrentVersion, Rules: not null } || file.Rules.Count > MaxRules
                || file.Rules.Any(rule => rule is not { HasKey: true }))
            {
                return false;
            }
            rules = file.Rules.ToArray();
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                     or System.Security.SecurityException or JsonException)
        {
            return false;
        }
    }

    private bool Save(List<ResponseRule> rules)
    {
        if (rules.Count > MaxRules)
        {
            return false;
        }
        // Empty stores use the same flushed atomic replacement as non-empty stores. Best-effort
        // deletion cannot prove revocation when another Windows handle denies deletion.
        var json = JsonSerializer.SerializeToUtf8Bytes(new RuleFile(CurrentVersion, rules));
        return json.Length <= MaxBytes && AtomicFile.TryWrite(_path, json);
    }

    /// <summary>Serializes read-modify-write of one rule file across threads and processes.</summary>
    private sealed class StoreLock : IDisposable
    {
        private readonly Mutex _mutex;

        private StoreLock(Mutex mutex) => _mutex = mutex;

        public static StoreLock Acquire(string path, TimeSpan wait)
        {
            var mutex = new Mutex(initiallyOwned: false, LockNameFor(path));
            bool held;
            try
            {
                held = mutex.WaitOne(wait);
            }
            catch (AbandonedMutexException)
            {
                held = true; // the previous holder died; the atomic write kept the file whole
            }
            if (!held)
            {
                mutex.Dispose();
                throw new IOException("Timed out waiting for the response-rule store lock.");
            }
            return new StoreLock(mutex);
        }

        public void Dispose()
        {
            _mutex.ReleaseMutex();
            _mutex.Dispose();
        }
    }

    internal static string LockNameFor(string path)
    {
        var key = Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(Path.GetFullPath(path).ToUpperInvariant())))[..32];
        return $@"Local\WinSight.ResponseRules.{key}";
    }
}
