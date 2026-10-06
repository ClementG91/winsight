using System.Text.Json;

using WinSight.Core;

namespace WinSight.Response;

/// <summary>
/// The per-user store of operator decisions (allow/ignore/block) for Guardian, ransomware and
/// camera/microphone. One versioned JSON file, written atomically and serialized across threads and
/// processes and Windows sessions by a persistent per-user exclusive file lock.
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

    private sealed record StoredEntry(ResponseRule Rule, ReadOnlyMemory<byte> Raw);

    /// <summary>The active rules for a scope, expired and reboot-scoped entries already dropped.</summary>
    public IReadOnlyList<ResponseRule> ActiveRules(RuleScopeKind scope) => ActiveRules(scope, out _);

    /// <summary>Active rules with their read status and the count of ignored invalid entries.</summary>
    public IReadOnlyList<ResponseRule> ActiveRules(RuleScopeKind scope, out RuleStoreResult result)
    {
        var now = _clock();
        return Load(out result)
            .Where(entry => IsSupported(entry.Rule))
            .Select(entry => entry.Rule)
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
        foreach (var entry in Load(out _))
        {
            var rule = entry.Rule;
            if (IsSupported(rule) && rule.IsActive(now) && rule.Matches(scope, item, imagePath, imageSha256, publisher))
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
        // Bound serialization work before a caller-controlled string can request a huge buffer.
        if ((long)(rule.Item?.Length ?? 0) + (rule.ImagePath?.Length ?? 0)
            + (rule.ImageSha256?.Length ?? 0) + (rule.Publisher?.Length ?? 0) > MaxBytes)
        {
            result = new(RuleStoreStatus.ByteLimit);
            return null;
        }
        try
        {
            using var gate = ResponseFileLock.AcquireWriter(_path, _lockWait);
            if (!TryLoadLocked(out var loaded, out result))
            {
                return null;
            }
            var rules = loaded.ToList();
            if (rules.Any(existing => existing.Rule.Id == rule.Id && !IsSupported(existing.Rule)))
            {
                result = result with { Status = RuleStoreStatus.UnsupportedIdentityCollision };
                return null;
            }
            rules.RemoveAll(existing => existing.Rule.Id == rule.Id);
            if (rules.Count >= MaxRules)
            {
                result = result with { Status = RuleStoreStatus.RuleLimit };
                return null;
            }
            rules.Add(new(rule, default));
            result = Save(rules, result.IgnoredEntries, result.RetainedUnsupportedEntries);
            return result.Durable ? rule : null;
        }
        catch (ResponseFileLockException ex)
        {
            result = new(LockFailure(ex.Status));
            return null;
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
            using var gate = ResponseFileLock.AcquireWriter(_path, _lockWait);
            if (!TryLoadLocked(out var loaded, out result))
            {
                return ResponseOutcome.Failed;
            }
            var rules = loaded.ToList();
            if (rules.RemoveAll(entry => entry.Rule.Id == id) == 0)
            {
                result = result with { Status = RuleStoreStatus.TargetNotFound };
                return ResponseOutcome.TargetNotFound;
            }
            result = Save(rules, result.IgnoredEntries, result.RetainedUnsupportedEntries);
            return result.Durable ? ResponseOutcome.Succeeded : ResponseOutcome.Failed;
        }
        catch (ResponseFileLockException ex)
        {
            result = new(LockFailure(ex.Status));
            return ResponseOutcome.Failed;
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
    private StoredEntry[] Load(out RuleStoreResult result)
    {
        try
        {
            using var gate = ResponseFileLock.AcquireReader(_path, _lockWait);
            var loaded = TryLoadLocked(out var rules, out result);
            if (!gate.IsCurrent)
            {
                result = new(RuleStoreStatus.LockUnavailable);
                return [];
            }
            return loaded ? rules : [];
        }
        catch (ResponseFileLockException ex)
        {
            result = new(LockFailure(ex.Status));
            return [];
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

    private bool TryLoadLocked(out StoredEntry[] rules, out RuleStoreResult result)
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
            var rawEntries = RawEntries(bytes);
            var valid = new List<StoredEntry>();
            var ignored = 0;
            var index = 0;
            foreach (var entry in entries.EnumerateArray())
            {
                var raw = rawEntries[index++];
                ResponseRule? rule = null;
                if (HasUniqueSemanticFields(entry))
                {
                    try
                    {
                        rule = entry.Deserialize<ResponseRule>(ReadOptions);
                    }
                    catch (JsonException)
                    {
                        // A malformed entry cannot disable structurally valid neighbors.
                    }
                }
                if (rule is null || !CanRetain(rule))
                {
                    ignored++;
                }
                else
                {
                    valid.Add(new(rule, raw));
                }
            }
            rules = valid.ToArray();
            result = new(RuleStoreStatus.Loaded, ignored, valid.Count(entry => !IsSupported(entry.Rule)));
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

    private static bool CanRetain(ResponseRule rule) => rule.Id != Guid.Empty && rule.HasKey
        && (rule.Duration != RuleDuration.Timed || rule.ExpiresUtc is not null)
        && (IsSupported(rule) || !Enum.IsDefined(rule.Scope) || !Enum.IsDefined(rule.Decision) || !Enum.IsDefined(rule.Duration));

    private static bool HasUniqueSemanticFields(JsonElement entry)
    {
        if (entry.ValueKind != JsonValueKind.Object)
        {
            return false;
        }
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in entry.EnumerateObject())
        {
            // JsonProperty.Name is decoded, so an escaped spelling cannot bypass this check.
            if (property.Name is "Id" or "Scope" or "Decision" or "Duration" or "CreatedUtc"
                or "ExpiresUtc" or "Item" or "ImagePath" or "ImageSha256" or "Publisher"
                && !seen.Add(property.Name))
            {
                return false;
            }
        }
        return true;
    }

    private static List<ReadOnlyMemory<byte>> RawEntries(byte[] bytes)
    {
        var values = new List<ReadOnlyMemory<byte>>();
        var reader = new Utf8JsonReader(bytes);
        reader.Read(); // The envelope has already been validated as an object.
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            var isRules = reader.ValueTextEquals("Rules"u8);
            reader.Read();
            if (!isRules)
            {
                reader.Skip();
                continue;
            }
            while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
            {
                var start = (int)reader.TokenStartIndex;
                reader.Skip();
                values.Add(bytes.AsMemory(start, (int)reader.BytesConsumed - start));
            }
            break;
        }
        return values;
    }

    private RuleStoreResult Save(List<StoredEntry> rules, int ignored, int retainedBeforeWrite)
    {
        var retained = rules.Count(entry => !IsSupported(entry.Rule));
        if (rules.Count > MaxRules)
        {
            return new(RuleStoreStatus.RuleLimit, ignored, retainedBeforeWrite);
        }
        try
        {
            using var stream = new BoundedRuleStream();
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject();
                writer.WriteNumber("Version", CurrentVersion);
                writer.WriteStartArray("Rules");
                foreach (var entry in rules)
                {
                    if (entry.Raw.IsEmpty)
                    {
                        JsonSerializer.Serialize(writer, entry.Rule);
                    }
                    else
                    {
                        // These exact slices came from a fully parsed and validated JSON envelope.
                        writer.WriteRawValue(entry.Raw.Span, skipInputValidation: true);
                    }
                }
                writer.WriteEndArray();
                writer.WriteEndObject();
                writer.Flush();
            }
            // Empty stores also use flushed atomic replacement, never best-effort deletion.
            var written = AtomicFile.TryWrite(_path, stream.ToArray());
            return new(written ? RuleStoreStatus.Written : RuleStoreStatus.WriteFailed,
                ignored, written ? retained : retainedBeforeWrite);
        }
        catch (RuleFileBudgetExceededException)
        {
            return new(RuleStoreStatus.ByteLimit, ignored, retainedBeforeWrite);
        }
    }

    private sealed class RuleFileBudgetExceededException : Exception
    {
    }

    private sealed class BoundedRuleStream : Stream
    {
        private readonly MemoryStream _stream = new();
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => _stream.CanWrite;
        public override long Length => _stream.Length;
        public override long Position
        {
            get => _stream.Position;
            set => throw new NotSupportedException();
        }
        public byte[] ToArray() => _stream.ToArray();
        public override void Flush() => _stream.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (Position + buffer.Length > MaxBytes)
            {
                throw new RuleFileBudgetExceededException();
            }
            _stream.Write(buffer);
        }
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override void WriteByte(byte value)
        {
            if (Position >= MaxBytes)
            {
                throw new RuleFileBudgetExceededException();
            }
            _stream.WriteByte(value);
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _stream.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    internal static string LockPathFor(string path) => ResponseFileLock.PathFor(path);

    private static RuleStoreStatus LockFailure(LocalFileLockStatus status) => status switch
    {
        LocalFileLockStatus.Busy => RuleStoreStatus.LockTimeout,
        LocalFileLockStatus.UnsafePath => RuleStoreStatus.UnsafeLockPath,
        _ => RuleStoreStatus.LockUnavailable,
    };
}
