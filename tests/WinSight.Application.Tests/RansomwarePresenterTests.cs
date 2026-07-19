using WinSight.Application;
using WinSight.Ransomware;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class RansomwarePresenterTests
{
    [Theory]
    [InlineData(RansomwareSignalKind.CanaryTouched, "RansomwareCanaryTouched")]
    [InlineData(RansomwareSignalKind.Rename, "RansomwareBurstDetected")]
    [InlineData(RansomwareSignalKind.Delete, "RansomwareBurstDetected")]
    [InlineData(RansomwareSignalKind.HighEntropyWrite, "RansomwareBurstDetected")]
    public void AlertMessageKey_MapsKindToMessage(RansomwareSignalKind kind, string expected) =>
        Assert.Equal(expected, RansomwarePresenter.AlertMessageKey(kind));

    [Theory]
    [InlineData(RansomwareSignalKind.CanaryTouched, true)]
    [InlineData(RansomwareSignalKind.Rename, false)]
    [InlineData(RansomwareSignalKind.Delete, false)]
    public void IsCritical_OnlyATouchedCanaryIsTheLoudestCase(RansomwareSignalKind kind, bool expected) =>
        Assert.Equal(expected, RansomwarePresenter.IsCritical(kind));

    [Fact]
    public void Detail_ShowsTheFileNameOnly_NeverTheDirectoryTree()
    {
        var detail = RansomwarePresenter.Detail(
            RansomwareSignalKind.CanaryTouched, @"C:\Users\someone\Documents\Private\payroll.xlsx");

        Assert.Contains("payroll.xlsx", detail, StringComparison.Ordinal);
        Assert.DoesNotContain(@"C:\Users", detail, StringComparison.Ordinal);
        Assert.DoesNotContain("Private", detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Detail_MissingPath_StillProducesSomethingUsable()
    {
        var detail = RansomwarePresenter.Detail(RansomwareSignalKind.Rename, null);
        Assert.False(string.IsNullOrWhiteSpace(detail));
    }

    [Fact]
    public void RansomwareHost_CreateDefault_DoesNoWorkUntilStarted()
    {
        using var monitor = RansomwareHost.CreateDefault();

        Assert.NotNull(monitor);
        Assert.Empty(monitor.Canaries); // nothing planted until Start()
    }
}
