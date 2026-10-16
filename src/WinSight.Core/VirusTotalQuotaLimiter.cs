using System.Diagnostics;
using System.Globalization;
using System.Security;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSight.Core;

/// <summary>Conservative local limits for a standard VirusTotal Community API key.</summary>
public sealed record VirusTotalQuotaLimits(
    int PerMinute = 4,
    int PerDay = 500,
    int PerMonth = 15_500);

public sealed record VirusTotalQuotaSnapshot(
    int UsedLastMinute,
    int UsedToday,
    int UsedThisMonth,
    bool RequestAllowed);

/// <summary>Admission result; infrastructure refusals do not establish measured quota usage.</summary>
public enum VirusTotalQuotaStatus
{
    Unknown,
    Acquired,
    QuotaExhausted,
    LockTimeout,
    UnsafePath,
    StateUnavailable,
    StateInvalidOrUnsupported,
    StateOverBudget,
    WriteFailed,
}

/// <summary>
/// Coordinates admissions using one local profile's canonical quota path, including across
/// Windows sessions. Older writers must be stopped before adopting the file-lock protocol.
/// No request is admitted when accounting cannot be read and persisted safely.
/// </summary>
public sealed class VirusTotalQuotaLimiter
{
    private const int MaximumStateBytes = 64 * 1024;
    private static readonly TimeSpan LockWait = TimeSpan.FromSeconds(2);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        NumberHandling = JsonNumberHandling.Strict,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties = false,
        MaxDepth = 8,
    };
    private readonly string _path;
    private readonly Func<DateTimeOffset> _utcNow;
    private readonly VirusTotalQuotaLimits _limits;

    public VirusTotalQuotaLimiter(
        string? path = null,
        Func<DateTimeOffset>? utcNow = null,
        VirusTotalQuotaLimits? limits = null)
    {
        _path = Path.GetFullPath(path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WinSight",
            "vt-quota-v1.json"));
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
        _limits = limits ?? new VirusTotalQuotaLimits();
        if (_limits.PerMinute is <= 0 or > 64 || _limits.PerDay <= 0 || _limits.PerMonth <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(limits), "Quota limits must be positive; the minute capacity is at most 64.");
        }
    }

    public static VirusTotalQuotaLimiter Default { get; } = new();

    public bool TryAcquire(out VirusTotalQuotaSnapshot snapshot) => TryAcquireAdmission(out snapshot, out _);

    /// <summary>
    /// On infrastructure refusal, snapshot counts are conservative placeholders at the configured
    /// limits. Only Acquired and QuotaExhausted establish measured usage.
    /// </summary>
    public bool TryAcquire(out VirusTotalQuotaSnapshot snapshot, out VirusTotalQuotaStatus status) =>
        TryAcquireAdmission(out snapshot, out status);

    private bool TryAcquireAdmission(out VirusTotalQuotaSnapshot snapshot, out VirusTotalQuotaStatus status)
    {
        snapshot = DeniedSnapshot();
        using var gate = AcquireGate(out status);
        if (gate is null) { return false; }

        QuotaState? state;
        bool missing;
        try
        {
            state = Load(out missing, out status);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            status = VirusTotalQuotaStatus.StateUnavailable;
            return false;
        }
        if (state is null) { return false; }

        // Observe the accounting time after the state was acquired, rather than before disk work.
        DateTimeOffset now;
        try { now = _utcNow().ToUniversalTime(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException
                                     or InvalidDataException or JsonException)
        {
            // Preserve the original conservative contract of the injectable clock as well.
            status = VirusTotalQuotaStatus.StateUnavailable;
            return false;
        }
        state = Normalize(state, now);
        if (state.RecentRequests.Count >= _limits.PerMinute || state.DayCount >= _limits.PerDay || state.MonthCount >= _limits.PerMonth)
        {
            snapshot = ToSnapshot(state, requestAllowed: false);
            status = VirusTotalQuotaStatus.QuotaExhausted;
            return false;
        }
        state.RecentRequests.Add(now);
        state.DayCount++;
        state.MonthCount++;
        // Never retry an uncertain publication. The next admission must reload durable accounting.
        if (!Save(state, replaceExisting: !missing))
        {
            status = VirusTotalQuotaStatus.WriteFailed;
            return false;
        }
        snapshot = ToSnapshot(state, requestAllowed: true);
        status = VirusTotalQuotaStatus.Acquired;
        return true;
    }

    private AutomaticFileAccess.LocalFileLock? AcquireGate(out VirusTotalQuotaStatus status)
    {
        status = VirusTotalQuotaStatus.UnsafePath;
        var leaf = Path.GetFileName(_path);
        if (leaf.Length == 0 || leaf.Length + ".lock".Length > 255) { return null; }
        var watch = Stopwatch.StartNew();
        try
        {
            while (watch.Elapsed < LockWait)
            {
                var gate = AutomaticFileAccess.TryAcquireExclusiveLockFile(_path + ".lock", out var attempt);
                if (gate is not null)
                {
                    status = VirusTotalQuotaStatus.Acquired;
                    return gate;
                }
                if (attempt != LocalFileLockStatus.Busy)
                {
                    status = attempt == LocalFileLockStatus.UnsafePath
                        ? VirusTotalQuotaStatus.UnsafePath : VirusTotalQuotaStatus.StateUnavailable;
                    return null;
                }
                var remaining = LockWait - watch.Elapsed;
                if (remaining > TimeSpan.Zero)
                {
                    Thread.Sleep(TimeSpan.FromMilliseconds(Math.Min(20, remaining.TotalMilliseconds)));
                }
            }
            status = VirusTotalQuotaStatus.LockTimeout;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            status = VirusTotalQuotaStatus.StateUnavailable;
        }
        return null;
    }

    private QuotaState? Load(out bool missing, out VirusTotalQuotaStatus status)
    {
        using var lease = AutomaticFileAccess.TryAcquire(_path, out missing);
        status = VirusTotalQuotaStatus.StateUnavailable;
        if (lease is null)
        {
            if (!missing) { return null; }
            status = VirusTotalQuotaStatus.Acquired;
            return new QuotaState();
        }
        return ReadAcquiredState(lease, out status);
    }

    private static QuotaState? ReadAcquiredState(AutomaticFileAccess.LocalPathLease lease, out VirusTotalQuotaStatus status)
    {
        status = VirusTotalQuotaStatus.StateUnavailable;
        if (lease.IsDirectory || !lease.DataIsLocal) { return null; }
        using var input = lease.OpenRead(FileOptions.SequentialScan);
        status = VirusTotalQuotaStatus.StateOverBudget;
        if (input.Length > MaximumStateBytes) { return null; }

        // Length captured by the attributes lease can be stale after an in-place write. Read at
        // most the physical budget plus one EOF sentinel before passing anything to the parser.
        var bytes = new byte[MaximumStateBytes + 1];
        var count = 0;
        while (count < bytes.Length)
        {
            var read = input.Read(bytes, count, bytes.Length - count);
            if (read == 0) { break; }
            count += read;
        }
        if (count > MaximumStateBytes) { return null; }
        status = VirusTotalQuotaStatus.StateInvalidOrUnsupported;
        QuotaState? state;
        try
        {
            // Stream deserialization accepts one initial BOM; its bytes count against the cap.
            using var bounded = new MemoryStream(bytes, 0, count, writable: false);
            state = JsonSerializer.Deserialize<QuotaState>(bounded, JsonOptions);
        }
        catch (JsonException) { return null; }
        if (state is null || state.DayCount < 0 || state.MonthCount < 0 || state.RecentRequests is null || state.RecentRequests.Count > 64
            || !DateOnly.TryParseExact(state.UtcDay, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var day)
            || !string.Equals(state.UtcMonth, day.ToString("yyyy-MM", CultureInfo.InvariantCulture), StringComparison.Ordinal))
        {
            return null;
        }
        status = VirusTotalQuotaStatus.StateUnavailable;
        if (!lease.IsCurrent()) { return null; }
        status = VirusTotalQuotaStatus.Acquired;
        return state;
    }

    private QuotaState Normalize(QuotaState state, DateTimeOffset now)
    {
        state.RecentRequests = state.RecentRequests
            .Where(request => request <= now && now - request < TimeSpan.FromMinutes(1))
            .Order()
            .ToList();

        var day = now.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        if (!string.Equals(state.UtcDay, day, StringComparison.Ordinal))
        {
            state.UtcDay = day;
            state.DayCount = 0;
        }

        var month = now.ToString("yyyy-MM", System.Globalization.CultureInfo.InvariantCulture);
        if (!string.Equals(state.UtcMonth, month, StringComparison.Ordinal))
        {
            state.UtcMonth = month;
            state.MonthCount = 0;
        }
        return state;
    }

    private bool Save(QuotaState state, bool replaceExisting)
    {
        try
        {
            var payload = JsonSerializer.SerializeToUtf8Bytes(state, JsonOptions);
            return payload.Length <= MaximumStateBytes && AtomicFile.TryWrite(_path, payload, replaceExisting: replaceExisting);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            return false;
        }
    }

    private VirusTotalQuotaSnapshot ToSnapshot(QuotaState state, bool requestAllowed) => new(
        state.RecentRequests.Count,
        state.DayCount,
        state.MonthCount,
        requestAllowed);

    private VirusTotalQuotaSnapshot DeniedSnapshot() => new(
        _limits.PerMinute,
        _limits.PerDay,
        _limits.PerMonth,
        RequestAllowed: false);

    private sealed class QuotaState
    {
        [JsonRequired]
        public List<DateTimeOffset> RecentRequests { get; set; } = [];
        [JsonRequired]
        public string UtcDay { get; set; } = string.Empty;
        [JsonRequired]
        public int DayCount { get; set; }
        [JsonRequired]
        public string UtcMonth { get; set; } = string.Empty;
        [JsonRequired]
        public int MonthCount { get; set; }
    }
}
