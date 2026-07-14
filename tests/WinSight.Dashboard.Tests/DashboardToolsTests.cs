using WinSight.Application;
using WinSight.Reporting;
using Xunit;

namespace WinSight.Dashboard.Tests;

[Collection(LocalizationCollection.Name)]
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

public sealed class DashboardWindowsActionsTests
{
    [Theory]
    [InlineData(DashboardWindowsAction.StartupApps)]
    [InlineData(DashboardWindowsAction.Privacy)]
    [InlineData(DashboardWindowsAction.Network)]
    [InlineData(DashboardWindowsAction.NetworkSettings)]
    [InlineData(DashboardWindowsAction.Firewall)]
    [InlineData(DashboardWindowsAction.Processes)]
    [InlineData(DashboardWindowsAction.InstalledApps)]
    [InlineData(DashboardWindowsAction.Certificates)]
    public void ConfiguredAction_ProducesAnAllowlistedLaunch(DashboardWindowsAction action)
    {
        var startInfo = DashboardWindowsActions.StartInfo(action);

        Assert.False(string.IsNullOrWhiteSpace(startInfo.FileName));
        Assert.DoesNotContain('"', startInfo.FileName);
        Assert.NotEqual("OpenWindowsTool", DashboardWindowsActions.LabelResource(action));
    }

    [Fact]
    public void MissingAction_CannotProduceALaunch()
    {
        Assert.Throws<InvalidOperationException>(() =>
            DashboardWindowsActions.StartInfo(DashboardWindowsAction.None));
    }
}

[Collection(LocalizationCollection.Name)]
public sealed class DashboardReportRouterTests
{
    private static readonly ToolReport Persistence = new("persistence", "one", []);
    private static readonly ToolReport Connections = new("connections", "two", []);

    [Fact]
    public void OverviewScan_FeedsOverviewAndOnlyTheSelectedCategory()
    {
        var reports = new[] { Persistence, Connections };

        var overview = DashboardReportRouter.Select(DashboardTools.ForCommand("all")!, "all", reports);
        var network = DashboardReportRouter.Select(DashboardTools.ForCommand("net")!, "all", reports);

        Assert.True(overview.Available);
        Assert.True(overview.Categorize);
        Assert.Equal(reports, overview.Reports);
        Assert.False(network.Categorize);
        Assert.Equal([Connections], network.Reports);
    }

    [Fact]
    public void CategoryWithoutReport_DoesNotReuseAnotherCategory()
    {
        var selection = DashboardReportRouter.Select(
            DashboardTools.ForCommand("net")!,
            "persistence",
            [Persistence]);

        Assert.False(selection.Available);
        Assert.Empty(selection.Reports);
    }

    [Fact]
    public void Overview_DoesNotMisrepresentASingleScanAsACompleteOverview()
    {
        var selection = DashboardReportRouter.Select(
            DashboardTools.ForCommand("all")!,
            "persistence",
            [Persistence]);

        Assert.False(selection.Available);
    }
}
