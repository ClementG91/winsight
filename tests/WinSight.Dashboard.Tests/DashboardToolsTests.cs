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

public sealed class DashboardReportCacheTests
{
    private static readonly ToolReport Persistence = new("persistence", "startup", []);
    private static readonly ToolReport Connections = new("connections", "network", []);
    private static readonly ToolReport Firewall = new("firewall", "firewall", []);

    [Fact]
    public void IndividualScan_DoesNotDiscardOverviewOrItsCategories()
    {
        var cache = new DashboardReportCache();
        cache.StoreOverview([Persistence, Connections], flaggedOnly: true);
        cache.Store(Firewall, flaggedOnly: true);

        var overview = cache.Select(DashboardTools.ForCommand("all")!, flaggedOnly: true);
        var persistence = cache.Select(DashboardTools.ForCommand("persistence")!, flaggedOnly: true);
        var firewall = cache.Select(DashboardTools.ForCommand("firewall")!, flaggedOnly: true);

        Assert.Equal([Persistence, Connections], overview.Reports);
        Assert.Equal([Persistence], persistence.Reports);
        Assert.Equal([Firewall], firewall.Reports);
    }

    [Fact]
    public void RefreshingIncludedCategory_UpdatesOverviewWithoutDiscardingOtherReports()
    {
        var refreshedPersistence = Persistence with { Summary = "refreshed" };
        var cache = new DashboardReportCache();
        cache.StoreOverview([Persistence, Connections], flaggedOnly: true);

        cache.Store(refreshedPersistence, flaggedOnly: true);

        Assert.Equal(
            [refreshedPersistence, Connections],
            cache.Select(DashboardTools.ForCommand("all")!, flaggedOnly: true).Reports);
    }

    [Fact]
    public void FilterModes_HaveIndependentHonestCaches()
    {
        var allPersistence = Persistence with { Summary = "all items" };
        var cache = new DashboardReportCache();
        cache.StoreOverview([Persistence], flaggedOnly: true);
        cache.Store(allPersistence, flaggedOnly: false);

        Assert.Equal(
            [Persistence],
            cache.Select(DashboardTools.ForCommand("persistence")!, flaggedOnly: true).Reports);
        Assert.Equal(
            [allPersistence],
            cache.Select(DashboardTools.ForCommand("persistence")!, flaggedOnly: false).Reports);
        Assert.False(cache.Select(DashboardTools.ForCommand("all")!, flaggedOnly: false).Available);
    }
}
