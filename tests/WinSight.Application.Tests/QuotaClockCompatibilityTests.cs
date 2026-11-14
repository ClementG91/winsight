using System.Security;
using System.Text.Json;

using WinSight.Core;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class QuotaClockCompatibilityTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-quota-clock-").FullName;
    private string StatePath => Path.Combine(_root, "quota.json");
    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void InvalidDataClockMustFailClosed() => AssertClosed(new InvalidDataException("synthetic-clock"));

    [Fact]
    public void JsonClockMustFailClosed() => AssertClosed(new JsonException("synthetic-clock"));

    [Theory]
    [InlineData("io")]
    [InlineData("access")]
    [InlineData("security")]
    public void ExistingConservativeClockFailuresRemainRefusals(string kind) => AssertClosed(kind switch
    {
        "io" => new IOException("synthetic-clock"),
        "access" => new UnauthorizedAccessException("synthetic-clock"),
        "security" => new SecurityException("synthetic-clock"),
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UnexpectedClockFailuresStillPropagateTheirExactObject(bool canceled)
    {
        Exception expected = canceled ? new OperationCanceledException("synthetic-clock") : new InvalidOperationException("synthetic-clock");
        var calls = 0;
        var guard = new VirusTotalQuotaLimiter(StatePath, () => { calls++; throw expected; });
        var actual = Record.Exception(() => guard.TryAcquire(out _));
        Assert.Equal(1, calls);
        Assert.Same(expected, actual);
        Assert.False(File.Exists(StatePath));
        AssertGateReleased();
    }

    private void AssertClosed(Exception expected)
    {
        var calls = 0;
        var guard = new VirusTotalQuotaLimiter(StatePath, () => { calls++; throw expected; });
        var actual = Record.Exception(() =>
        {
            Assert.False(guard.TryAcquire(out var snapshot, out var status));
            Assert.Equal(VirusTotalQuotaStatus.StateUnavailable, status);
            Assert.Equal(new VirusTotalQuotaSnapshot(4, 500, 15500, false), snapshot);
        });
        Assert.Equal(1, calls);
        Assert.Null(actual);
        Assert.False(File.Exists(StatePath));
        AssertGateReleased();
    }

    private void AssertGateReleased()
    {
        Assert.True(File.Exists(StatePath + ".lock"));
        using var gate = AutomaticFileAccess.TryAcquireExistingLockFile(StatePath + ".lock", out var status);
        Assert.NotNull(gate);
        Assert.Equal(LocalFileLockStatus.Acquired, status);
    }
}
