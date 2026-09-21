using WinSight.Application;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// How long the machine slept, as the presence report says it. The format it replaced showed the
/// hours component only, so 30 hours asleep read "06:00".
/// </summary>
public sealed class SleepDurationTests
{
    [Theory]
    [InlineData(0, 0, 45, "00:45")]
    [InlineData(0, 6, 5, "06:05")]
    [InlineData(1, 6, 0, "1 d 06:00")]
    [InlineData(9, 23, 59, "9 d 23:59")]
    public void TheDaysAreKept(int days, int hours, int minutes, string expected) =>
        Assert.Equal(expected, Adapters.SleepDuration(new TimeSpan(days, hours, minutes, 0)));
}
