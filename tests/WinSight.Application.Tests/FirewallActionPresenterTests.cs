using WinSight.Application;
using WinSight.Reporting;
using Xunit;

namespace WinSight.Application.Tests;

public sealed class FirewallActionPresenterTests
{
    private static ReportItem Item(params (string Key, string? Value)[] fields) =>
        new(Severity.Info, "t", "d", fields.ToDictionary(f => f.Key, f => f.Value));

    [Theory]
    [InlineData("connections", "image")]
    [InlineData("processes", "path")]
    [InlineData("persistence", "image")]
    public void BlockableExecutable_ReturnsExecutable_ForOwningTools(string tool, string key)
    {
        var path = FirewallActionPresenter.BlockableExecutable(tool, Item((key, @"C:\apps\a.exe")));
        Assert.Equal(@"C:\apps\a.exe", path);
    }

    [Fact]
    public void BlockableExecutable_Null_ForNonProgramTool() =>
        Assert.Null(FirewallActionPresenter.BlockableExecutable("certificates", Item(("image", @"C:\a.exe"))));

    [Fact]
    public void BlockableExecutable_Null_ForDllImage() =>
        Assert.Null(FirewallActionPresenter.BlockableExecutable("persistence", Item(("image", @"C:\evil.dll"))));

    [Fact]
    public void BlockableExecutable_Null_ForRelativeOrMissingPath()
    {
        Assert.Null(FirewallActionPresenter.BlockableExecutable("processes", Item(("path", "a.exe"))));
        Assert.Null(FirewallActionPresenter.BlockableExecutable("processes", Item(("path", null))));
        Assert.Null(FirewallActionPresenter.BlockableExecutable("processes", Item()));
    }
}
