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
        };

        Assert.Equal(expected.Order(), Adapters.SnapshotCommands.Order());
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
