using WinSight.Application;
using Xunit;

namespace WinSight.Dashboard.Tests;

public sealed class DashboardToolsTests
{
    [Fact]
    public void Catalog_HasUniqueCommandsAndLabels()
    {
        Assert.Equal(DashboardTools.All.Count, DashboardTools.All.Select(tool => tool.Command).Distinct().Count());
        Assert.Equal(DashboardTools.All.Count, DashboardTools.All.Select(tool => tool.Label).Distinct().Count());
    }

    [Fact]
    public void Catalog_ExposesOverviewAndEverySnapshotCommand()
    {
        var commands = DashboardTools.All.Select(tool => tool.Command).ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.Contains("all", commands);
        Assert.All(Adapters.SnapshotCommands, command => Assert.Contains(command, commands));
    }
}
