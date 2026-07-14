using System.Collections;
using System.Globalization;
using System.Resources;
using Xunit;

namespace WinSight.Dashboard.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class LocalizationCollection
{
    public const string Name = "dashboard-localization";
}

[Collection(LocalizationCollection.Name)]
public sealed class LocalizationTests
{
    [Fact]
    public void SupportedLanguages_ContainsEnglishFrenchAndSpanish()
    {
        var codes = LocalizationManager.Instance.SupportedLanguages.Select(language => language.Code);

        Assert.Equal(["en", "fr", "es"], codes);
    }

    [Theory]
    [InlineData("en", "Overview")]
    [InlineData("fr-FR", "Vue d’ensemble")]
    [InlineData("es-ES", "Vista general")]
    public void CultureSwitch_LocalizesTheCompleteToolCatalog(string culture, string expectedOverview)
    {
        var localization = LocalizationManager.Instance;
        var original = localization.CurrentCode;
        try
        {
            localization.SetCulture(culture);
            DashboardTools.Reload();

            Assert.Equal(expectedOverview, DashboardTools.ForCommand("all")?.Label);
            Assert.All(DashboardTools.All, tool =>
            {
                Assert.False(string.IsNullOrWhiteSpace(tool.Label));
                Assert.False(string.IsNullOrWhiteSpace(tool.ShortDescription));
                Assert.False(string.IsNullOrWhiteSpace(tool.Description));
                Assert.False(string.IsNullOrWhiteSpace(tool.Guidance));
                Assert.DoesNotContain("[Tool", tool.Label, StringComparison.Ordinal);
            });
        }
        finally
        {
            localization.SetCulture(original);
            DashboardTools.Reload();
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("de-DE")]
    [InlineData("invalid")]
    public void NormalizeCode_UsesEnglishForUnsupportedCultures(string? culture)
    {
        Assert.Equal("en", LocalizationManager.NormalizeCode(culture));
    }

    [Theory]
    [InlineData("fr")]
    [InlineData("es")]
    public void SatelliteResource_TranslatesEveryNeutralKey(string cultureName)
    {
        var resources = new ResourceManager(
            "WinSight.Dashboard.Localization.Strings",
            typeof(LocalizationManager).Assembly);
        var neutral = resources.GetResourceSet(CultureInfo.InvariantCulture, true, false);
        var localized = resources.GetResourceSet(CultureInfo.GetCultureInfo(cultureName), true, false);

        Assert.NotNull(neutral);
        Assert.NotNull(localized);
        foreach (DictionaryEntry entry in neutral)
        {
            var key = Assert.IsType<string>(entry.Key);
            Assert.False(
                string.IsNullOrWhiteSpace(localized.GetString(key)),
                $"Missing {cultureName} localization for resource '{key}'.");
        }
    }
}
