using Xunit;

namespace WinSight.Application.Tests;

public sealed class AdaptersTests
{
    [Fact]
    public void SnapshotCommands_AreUniqueAndComplete()
    {
        var expected = new[]
        {
            "persistence", "av", "net", "dns", "firewall", "processes", "modules", "extensions", "certs", "hosts",
            "input", "drivers", "integrity", "hijack",
        };

        Assert.Equal(expected.Order(), Adapters.SnapshotCommands.Order());
    }

    [Fact]
    public void OverviewCommands_AreSupportedAndUnique()
    {
        Assert.Equal(Adapters.OverviewCommands.Count, Adapters.OverviewCommands.Distinct().Count());
        Assert.All(Adapters.OverviewCommands, command => Assert.Contains(command, Adapters.SnapshotCommands));
    }

    [Fact]
    public void RunOverview_HonoursPreCancelledTokenBeforeScanning()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.Throws<OperationCanceledException>(() => Adapters.RunOverview(cancellationToken: cts.Token));
    }

    [Theory]
    [InlineData(0, 7, 0)]
    [InlineData(3, 7, 43)]
    [InlineData(7, 7, 100)]
    [InlineData(1, 0, 0)]
    [InlineData(9, 7, 100)]
    [InlineData(-1, 7, 0)]
    public void ScanProgress_ComputesBoundedPercentage(int completed, int total, int expected)
    {
        Assert.Equal(expected, new ScanProgress(completed, total, "test").Percent);
    }

    [Fact]
    public void Run_RejectsUnknownCommandBeforeStartingAScan()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Adapters.Run("unknown"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void Run_RejectsEmptyCommand(string command)
    {
        Assert.Throws<ArgumentException>(() => Adapters.Run(command));
    }
}
