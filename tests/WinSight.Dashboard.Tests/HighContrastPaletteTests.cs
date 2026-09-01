using System.Windows;
using System.Windows.Media;

using WinSight.Dashboard;
using Xunit;

namespace WinSight.Dashboard.Tests;

/// <summary>
/// The dashboard follows Windows' high-contrast setting.
/// </summary>
/// <remarks>
/// <b>What it did before.</b> The palette is seven hard-coded hex values - a reasonable way to keep
/// a card, a border and a button edge from drifting apart, and it meant the dashboard rendered
/// identically whatever the user had told Windows they needed. Turning on high contrast, which is
/// the setting people with low vision actually use, changed nothing: the same mid-slate text on the
/// same white surface.
/// </remarks>
[Collection(LocalizationCollection.Name)]
public sealed class HighContrastPaletteTests
{
    /// <summary>An application object carrying the shipped palette, without starting a UI.</summary>
    private static ResourceDictionary Designed()
    {
        HighContrastPalette.Forget();
        var application = new ResourceDictionary();
        application["AccentBrush"] = new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xEB));
        application["AccentPressedBrush"] = new SolidColorBrush(Color.FromRgb(0x1D, 0x4E, 0xD8));
        application["SurfaceBrush"] = new SolidColorBrush(Colors.White);
        application["SurfaceEdgeBrush"] = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1));
        application["TextBrush"] = new SolidColorBrush(Color.FromRgb(0x0F, 0x17, 0x2A));
        application["DangerBrush"] = new SolidColorBrush(Color.FromRgb(0xB9, 0x1C, 0x1C));
        application["SuccessBrush"] = new SolidColorBrush(Color.FromRgb(0x15, 0x80, 0x3D));
        return application;
    }

    [Fact]
    public void HighContrastReplacesEveryDesignedBrushWithASystemOne()
    {
        var application = Designed();

        HighContrastPalette.Apply(application, highContrast: true);

        Assert.All(HighContrastPalette.Keys, key =>
            Assert.Contains(
                application[key],
                new object[]
                {
                    SystemColors.HighlightBrush, SystemColors.HotTrackBrush,
                    SystemColors.WindowBrush, SystemColors.ActiveBorderBrush,
                    SystemColors.WindowTextBrush,
                }));
    }

    /// <summary>
    /// Leaving high contrast restores exactly what the product ships, not an approximation of it.
    /// </summary>
    [Fact]
    public void LeavingHighContrastRestoresTheDesignedPalette()
    {
        var application = Designed();
        var before = HighContrastPalette.Keys
            .ToDictionary(key => key, key => application[key]);

        HighContrastPalette.Apply(application, highContrast: true);
        HighContrastPalette.Apply(application, highContrast: false);

        Assert.All(HighContrastPalette.Keys, key =>
            Assert.Same(before[key], application[key]));
    }

    /// <summary>
    /// Every key the palette defines is covered. A brush added to App.xaml and forgotten here would
    /// stay hard-coded in high contrast, which is exactly the defect being fixed.
    /// </summary>
    [Fact]
    public void ThePaletteCoversEveryBrushTheApplicationDefines()
    {
        var xaml = File.ReadAllText(Path.Combine(
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..")),
            "src", "WinSight.Dashboard", "App.xaml"));
        var declared = System.Text.RegularExpressions.Regex
            .Matches(xaml, @"<SolidColorBrush x:Key=""(?<key>[^""]+)""")
            .Select(match => match.Groups["key"].Value)
            .ToArray();

        Assert.NotEmpty(declared);
        Assert.Equal(declared.Order(), HighContrastPalette.Keys.Order());
    }
}
