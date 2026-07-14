using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

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

/// <summary>
/// Coordinates VirusTotal request accounting across WinSight processes for one
/// Windows user. The local guard is intentionally stricter than relying on HTTP 429:
/// no retry is sent and a request is refused when accounting cannot be persisted.
/// </summary>
public sealed class VirusTotalQuotaLimiter
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _path;
    private readonly string _mutexName;
    private readonly Func<DateTimeOffset> _utcNow;
    private readonly VirusTotalQuotaLimits _limits;

    public VirusTotalQuotaLimiter(
        string? path = null,
        Func<DateTimeOffset>? utcNow = null,
        VirusTotalQuotaLimits? limits = null)
    {
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WinSight",
            "vt-quota-v1.json");
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
        _limits = limits ?? new VirusTotalQuotaLimits();
        if (_limits.PerMinute <= 0 || _limits.PerDay <= 0 || _limits.PerMonth <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(limits), "Quota limits must be positive.");
        }

        var identity = SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(_path).ToUpperInvariant()));
        _mutexName = $"Local\\WinSight.VirusTotalQuota.{Convert.ToHexString(identity.AsSpan(0, 8))}";
    }

    public static VirusTotalQuotaLimiter Default { get; } = new();

    public bool TryAcquire(out VirusTotalQuotaSnapshot snapshot)
    {
        using var mutex = new Mutex(initiallyOwned: false, _mutexName);
        var acquired = false;
        try
        {
            try
            {
                acquired = mutex.WaitOne(TimeSpan.FromSeconds(2));
            }
            catch (AbandonedMutexException)
            {
                acquired = true;
            }

            if (!acquired)
            {
                snapshot = DeniedSnapshot();
                return false;
            }

            var now = _utcNow().ToUniversalTime();
            var state = Normalize(Load(), now);
            var allowed = state.RecentRequests.Count < _limits.PerMinute &&
                          state.DayCount < _limits.PerDay &&
                          state.MonthCount < _limits.PerMonth;
            if (!allowed)
            {
                snapshot = ToSnapshot(state, requestAllowed: false);
                return false;
            }

            state.RecentRequests.Add(now);
            state.DayCount++;
            state.MonthCount++;
            Save(state);
            snapshot = ToSnapshot(state, requestAllowed: true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException
                                     or InvalidDataException or JsonException)
        {
            snapshot = DeniedSnapshot();
            return false;
        }
        finally
        {
            if (acquired)
            {
                mutex.ReleaseMutex();
            }
        }
    }

    private QuotaState Load()
    {
        if (!File.Exists(_path))
        {
            return new QuotaState();
        }

        var state = JsonSerializer.Deserialize<QuotaState>(File.ReadAllText(_path), JsonOptions)
                    ?? throw new InvalidDataException("VirusTotal quota state is empty.");
        if (state.DayCount < 0 || state.MonthCount < 0 ||
            state.RecentRequests is null || state.RecentRequests.Count > 64)
        {
            throw new InvalidDataException("VirusTotal quota state is invalid.");
        }
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

    private void Save(QuotaState state)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var temporaryPath = _path + ".tmp";
        try
        {
            File.WriteAllText(temporaryPath, JsonSerializer.Serialize(state, JsonOptions));
            File.Move(temporaryPath, _path, overwrite: true);
        }
        finally
        {
            try
            {
                File.Delete(temporaryPath);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // The authoritative state was either moved atomically or left intact.
            }
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
        public List<DateTimeOffset> RecentRequests { get; set; } = [];
        public string UtcDay { get; set; } = string.Empty;
        public int DayCount { get; set; }
        public string UtcMonth { get; set; } = string.Empty;
        public int MonthCount { get; set; }
    }
}
