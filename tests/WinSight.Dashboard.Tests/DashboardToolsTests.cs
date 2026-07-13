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

    [Fact]
    public void Catalog_HasPlainLanguageHelpForEveryTool()
    {
        Assert.All(DashboardTools.All, tool =>
        {
            Assert.False(string.IsNullOrWhiteSpace(tool.ShortDescription));
            Assert.False(string.IsNullOrWhiteSpace(tool.Description));
            Assert.False(string.IsNullOrWhiteSpace(tool.Guidance));
            Assert.Same(tool, DashboardTools.ForCommand(tool.Command));
            Assert.Same(tool, DashboardTools.ForReport(tool.ReportName));
        });
    }
}
