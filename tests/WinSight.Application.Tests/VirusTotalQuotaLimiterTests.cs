using WinSight.Core;
using Xunit;

namespace WinSight.Application.Tests;

public sealed class VirusTotalQuotaLimiterTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "winsight-quota-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public void Guard_EnforcesRollingMinuteDailyAndMonthlyLimits()
    {
        var now = new DateTimeOffset(2026, 7, 14, 12, 0, 0, TimeSpan.Zero);
        var guard = new VirusTotalQuotaLimiter(
            Path.Combine(_directory, "quota.json"),
            () => now,
            new VirusTotalQuotaLimits(PerMinute: 2, PerDay: 3, PerMonth: 4));

        Assert.True(guard.TryAcquire(out _));
        Assert.True(guard.TryAcquire(out var second));
        Assert.Equal(2, second.UsedLastMinute);
        Assert.False(guard.TryAcquire(out _));

        now = now.AddSeconds(61);
        Assert.True(guard.TryAcquire(out var third));
        Assert.Equal(3, third.UsedToday);
        Assert.False(guard.TryAcquire(out _));

        now = now.AddDays(1);
        Assert.True(guard.TryAcquire(out var fourth));
        Assert.Equal(1, fourth.UsedToday);
        Assert.Equal(4, fourth.UsedThisMonth);
        Assert.False(guard.TryAcquire(out _));

        now = new DateTimeOffset(2026, 8, 1, 0, 0, 0, TimeSpan.Zero);
        Assert.True(guard.TryAcquire(out var nextMonth));
        Assert.Equal(1, nextMonth.UsedThisMonth);
    }

    [Fact]
    public void Guard_SharesPersistentAccountingAcrossInstances()
    {
        var path = Path.Combine(_directory, "shared.json");
        var now = new DateTimeOffset(2026, 7, 14, 12, 0, 0, TimeSpan.Zero);
        var limits = new VirusTotalQuotaLimits(2, 10, 10);
        var first = new VirusTotalQuotaLimiter(path, () => now, limits);
        var second = new VirusTotalQuotaLimiter(path, () => now, limits);

        Assert.True(first.TryAcquire(out _));
        Assert.True(second.TryAcquire(out var snapshot));
        Assert.Equal(2, snapshot.UsedLastMinute);
        Assert.False(first.TryAcquire(out _));
    }

    [Fact]
    public void Guard_FailsClosedWhenAccountingStateIsCorrupt()
    {
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, "corrupt.json");
        File.WriteAllText(path, "not-json");
        var guard = new VirusTotalQuotaLimiter(path);

        Assert.False(guard.TryAcquire(out var snapshot));
        Assert.False(snapshot.RequestAllowed);
    }

    [Fact]
    public void Guard_FailsClosedBeforeReadingOversizedAccountingState()
    {
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, "oversized.json");
        File.WriteAllBytes(path, new byte[65 * 1024]);
        var guard = new VirusTotalQuotaLimiter(path);

        Assert.False(guard.TryAcquire(out var snapshot));
        Assert.False(snapshot.RequestAllowed);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (DirectoryNotFoundException)
        {
        }
    }
}
