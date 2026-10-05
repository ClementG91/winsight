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
    private static readonly JsonSerializerOptions ReadOptions = new() { RespectRequiredConstructorParameters = true };

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
    public IReadOnlyList<ResponseRule> ActiveRules(RuleScopeKind scope) => ActiveRules(scope, out _);

    /// <summary>Active rules with their read status and the count of ignored invalid entries.</summary>
    public IReadOnlyList<ResponseRule> ActiveRules(RuleScopeKind scope, out RuleStoreResult result)
    {
        var now = _clock();
        return Load(out result)
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
        foreach (var rule in Load(out _))
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
    public ResponseRule? Add(ResponseRule rule) => Add(rule, out _);

    /// <summary>Adds with an explicit durable-write or refusal status.</summary>
    public ResponseRule? Add(ResponseRule rule, out RuleStoreResult result)
    {
        ArgumentNullException.ThrowIfNull(rule);
        result = new(RuleStoreStatus.InvalidRule);
        if (!IsSupported(rule))
        {
            return null;
        }
        try
        {
            using var gate = StoreLock.Acquire(_path, _lockWait);
            if (!TryLoadLocked(out var loaded, out result))
            {
                return null;
            }
            var rules = loaded.ToList();
            rules.RemoveAll(existing => existing.Id == rule.Id);
            if (rules.Count >= MaxRules)
            {
                result = result with { Status = RuleStoreStatus.RuleLimit };
                return null;
            }
            rules.Add(rule);
            result = Save(rules, result.IgnoredEntries);
            return result.Durable ? rule : null;
        }
        catch (Exception ex) when (IsStoreUnavailable(ex))
        {
            result = new(RuleStoreStatus.Unavailable);
            return null;
        }
    }

    /// <summary>Removes the rule with this id. True when one was removed and the store was written.</summary>
    public bool Remove(Guid id) => RemoveWithOutcome(id) == ResponseOutcome.Succeeded;

    /// <summary>
    /// Removes a rule durably, distinguishing an absent id from unreadable or unwritable storage.
    /// An unavailable store is never evidence that the rule was absent or revoked.
    /// </summary>
    public ResponseOutcome RemoveWithOutcome(Guid id) => RemoveWithOutcome(id, out _);

    /// <summary>Durably removes a rule or gives an exact storage refusal/confirmed absence.</summary>
    public ResponseOutcome RemoveWithOutcome(Guid id, out RuleStoreResult result)
    {
        try
        {
            using var gate = StoreLock.Acquire(_path, _lockWait);
            if (!TryLoadLocked(out var loaded, out result))
            {
                return ResponseOutcome.Failed;
            }
            var rules = loaded.ToList();
            if (rules.RemoveAll(rule => rule.Id == id) == 0)
            {
                result = result with { Status = RuleStoreStatus.TargetNotFound };
                return ResponseOutcome.TargetNotFound;
            }
            result = Save(rules, result.IgnoredEntries);
            return result.Durable ? ResponseOutcome.Succeeded : ResponseOutcome.Failed;
        }
        catch (Exception ex) when (IsStoreUnavailable(ex))
        {
            result = new(RuleStoreStatus.Unavailable);
            return ResponseOutcome.Failed;
        }
    }

    /// <summary>
    /// Reads the rules. An unavailable store reads as "no rules", which fails open: a monitor that
    /// cannot read its rules alerts rather than silently suppressing. This path must never throw,
    /// because monitors consult it on every detection.
    /// </summary>
    private ResponseRule[] Load(out RuleStoreResult result)
    {
        try
        {
            using var gate = StoreLock.Acquire(_path, _lockWait);
            return TryLoadLocked(out var rules, out result) ? rules : [];
        }
        catch (Exception ex) when (IsStoreUnavailable(ex))
        {
            result = new(RuleStoreStatus.Unavailable);
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

    private bool TryLoadLocked(out ResponseRule[] rules, out RuleStoreResult result)
    {
        rules = [];
        result = new(RuleStoreStatus.Unavailable);
        try
        {
            using var lease = AutomaticFileAccess.TryAcquire(_path, out var missing);
            if (lease is null)
            {
                // The same failed native open must confirm absence; no second preflight can
                // turn a sharing or access failure into a healthy empty store.
                result = new(missing ? RuleStoreStatus.Missing : RuleStoreStatus.Unavailable);
                return missing;
            }
            if (lease.IsDirectory)
            {
                return false;
            }
            if (lease.Length > MaxBytes)
            {
                result = new(RuleStoreStatus.ByteLimit);
                return false;
            }
            using var stream = lease.OpenRead();
            var bytes = new byte[(int)lease.Length];
            stream.ReadExactly(bytes);
            if (!lease.IsCurrent())
            {
                return false;
            }
            using var document = JsonDocument.Parse(bytes);
            var value = document.RootElement;
            result = new(RuleStoreStatus.InvalidFormat);
            if (value.ValueKind != JsonValueKind.Object
                || value.EnumerateObject().Count(property => property.NameEquals("Version")) != 1
                || value.EnumerateObject().Count(property => property.NameEquals("Rules")) != 1
                || !value.TryGetProperty("Version", out var version) || version.ValueKind != JsonValueKind.Number
                || !version.TryGetInt32(out var number))
            {
                return false;
            }
            if (number != CurrentVersion)
            {
                result = new(RuleStoreStatus.UnsupportedVersion);
                return false;
            }
            var entries = value.GetProperty("Rules");
            if (entries.ValueKind != JsonValueKind.Array)
            {
                return false;
            }
            // Bound raw input work as well as stored valid rules; invalid rows consume input budget.
            if (entries.GetArrayLength() > MaxRules)
            {
                result = new(RuleStoreStatus.RuleLimit);
                return false;
            }
            var valid = new List<ResponseRule>();
            var ignored = 0;
            foreach (var entry in entries.EnumerateArray())
            {
                ResponseRule? rule = null;
                try
                {
                    rule = entry.Deserialize<ResponseRule>(ReadOptions);
                }
                catch (JsonException)
                {
                    // The envelope is valid JSON. A malformed entry cannot disable valid neighbors.
                }
                if (rule is null || !IsSupported(rule))
                {
                    ignored++;
                }
                else
                {
                    valid.Add(rule);
                }
            }
            rules = valid.ToArray();
            result = new(RuleStoreStatus.Loaded, ignored);
            return true;
        }
        catch (JsonException)
        {
            result = new(RuleStoreStatus.InvalidJson);
            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            result = new(RuleStoreStatus.Unavailable);
            return false;
        }
    }

    private static bool IsSupported(ResponseRule rule) => rule.Id != Guid.Empty && rule.HasKey
        && Enum.IsDefined(rule.Scope) && Enum.IsDefined(rule.Decision)
        && (rule.Duration == RuleDuration.Permanent
            || rule.Duration == RuleDuration.Timed && rule.ExpiresUtc is not null);

    private RuleStoreResult Save(List<ResponseRule> rules, int ignored)
    {
        if (rules.Count > MaxRules)
        {
            return new(RuleStoreStatus.RuleLimit, ignored);
        }
        // Empty stores use the same flushed atomic replacement as non-empty stores. Best-effort
        // deletion cannot prove revocation when another Windows handle denies deletion.
        var json = JsonSerializer.SerializeToUtf8Bytes(new RuleFile(CurrentVersion, rules));
        return new(json.Length > MaxBytes ? RuleStoreStatus.ByteLimit
            : AtomicFile.TryWrite(_path, json) ? RuleStoreStatus.Written : RuleStoreStatus.WriteFailed, ignored);
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
        return $@"Global\WinSight.ResponseRules.{key}";
    }
}
