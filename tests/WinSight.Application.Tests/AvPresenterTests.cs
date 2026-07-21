using WinSight.AvMonitor;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// What an alert shows. Found by looking at a real balloon: the full path wrapped over four lines
/// and was truncated before it identified anything, while putting the operator's folder layout on
/// screen for no benefit.
/// </summary>
public sealed class AvPresenterTests
{
    private static DeviceUsage Usage(string app, bool packaged = false) =>
        new(DeviceKind.Microphone, app, packaged, LastStart: null, LastStop: null, Active: true);

    [Fact]
    public void ADesktopAppIsShownByItsFileNameNotItsPath()
    {
        Assert.Equal("Discord.exe", AvPresenter.DisplayName(
            Usage(@"C:\Users\chome\AppData\Local\Discord\app-1.0.9248\Discord.exe")));
    }

    [Fact]
    public void ThePathIsNotLeakedIntoTheAlert()
    {
        // A balloon can be shoulder-surfed or land in a screenshot. The journal keeps the full
        // path; the alert only needs to answer "what is using my microphone".
        var shown = AvPresenter.DisplayName(Usage(@"C:\Users\chome\Secret Project\tool.exe"));

        Assert.DoesNotContain(@"\", shown, StringComparison.Ordinal);
        Assert.DoesNotContain("Secret", shown, StringComparison.Ordinal);
    }

    [Fact]
    public void APackagedAppKeepsItsFamilyName()
    {
        // A package family name has no directories in it; trimming at a separator would mangle it.
        const string family = "Microsoft.WindowsCamera_8wekyb3d8bbwe";

        Assert.Equal(family, AvPresenter.DisplayName(Usage(family, packaged: true)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void AnAppWithNoNameDegradesHonestly(string app)
    {
        Assert.Equal("(unknown)", AvPresenter.DisplayName(Usage(app)));
    }

    [Fact]
    public void ATrailingSeparatorDoesNotProduceAnEmptyName()
    {
        Assert.Equal("app", AvPresenter.DisplayName(Usage(@"C:\tools\app\")));
    }
}
