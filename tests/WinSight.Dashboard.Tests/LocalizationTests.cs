using System.Collections;
using System.Globalization;
using System.Resources;
using WinSight.Firewall;
using WinSight.Persistence;
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

    /// <summary>
    /// Keys whose translation is deliberately byte-identical to English, and why. Everything here is
    /// either a pure format string with no prose, or a Windows proper noun that must not be
    /// translated because it names a real registry key or mechanism an operator will search for.
    /// </summary>
    private static readonly HashSet<string> DeliberatelyUntranslated = new(StringComparer.Ordinal)
    {
        // Pure format strings: placeholders and punctuation only, no words to translate.
        "ConnectionProcessState",
        "FindingSelectionFormat",
        "FirewallRuleTitle",
        "ModuleLoadedByProcess",
        "ProcessWithPid",
        "ProgressFormat",
        "ResultsSummary",
        "SensorItemTitle",
        // Windows mechanism names. Translating these would stop an operator finding them in
        // regedit, Autoruns or Microsoft's own documentation.
        "PersistenceVectorActiveSetup",
        "PersistenceVectorBootExecute",
        "PersistenceVectorWinlogon",
        // Words that are genuinely spelled the same in the target language.
        "InfoSeverity",
        "RansomwareProtectionShort",
        "SensorMicrophone",
    };

    /// <summary>
    /// The sibling test only proves a translation is non-empty. Copying the English string into
    /// fr/es satisfies that while shipping an untranslated UI, so a new key can rot in silently.
    /// This pins the identical set: a new untranslated key fails, and a key that later gets a real
    /// translation must be removed from the list, which keeps the list from becoming a dumping
    /// ground.
    /// </summary>
    [Theory]
    [InlineData("fr")]
    [InlineData("es")]
    public void SatelliteResource_HasNoUndeclaredUntranslatedString(string cultureName)
    {
        var resources = new ResourceManager(
            "WinSight.Dashboard.Localization.Strings",
            typeof(LocalizationManager).Assembly);
        var neutral = resources.GetResourceSet(CultureInfo.InvariantCulture, true, false);
        var localized = resources.GetResourceSet(CultureInfo.GetCultureInfo(cultureName), true, false);

        Assert.NotNull(neutral);
        Assert.NotNull(localized);

        var undeclared = new List<string>();
        foreach (DictionaryEntry entry in neutral)
        {
            var key = (string)entry.Key;
            if (entry.Value is not string english || localized.GetString(key) is not { } translated)
            {
                continue;
            }
            if (string.Equals(english, translated, StringComparison.Ordinal)
                && !DeliberatelyUntranslated.Contains(key))
            {
                undeclared.Add($"{key} = \"{english}\"");
            }
        }

        // Deliberately one-directional. The reverse check - "this key is in the list but is now
        // translated, so remove it" - cannot be done per-culture against a set that is the union of
        // both languages: a word identical in French and translated in Spanish would fail it for no
        // reason. A slightly generous list is a hygiene matter; an untranslated string reaching a
        // user is the defect worth failing on.
        Assert.True(
            undeclared.Count == 0,
            $"These {cultureName} strings are identical to English but not declared deliberate. "
            + "Translate them, or add them to DeliberatelyUntranslated with a reason: "
            + string.Join("; ", undeclared));
    }

    [Theory]
    [InlineData("en")]
    [InlineData("fr")]
    [InlineData("es")]
    public void StructuredSecurityEnums_HaveExplicitLocalizedLabels(string culture)
    {
        var localization = LocalizationManager.Instance;
        var original = localization.CurrentCode;
        try
        {
            localization.SetCulture(culture);
            Assert.All(Enum.GetNames<AutostartVector>(), name =>
                Assert.NotEqual("missing", localization.GetOrFallback($"PersistenceVector{name}", "missing")));
            Assert.All(Enum.GetNames<PersistenceStatus>(), name =>
                Assert.NotEqual("missing", localization.GetOrFallback($"PersistenceStatus{name}", "missing")));
            Assert.All(Enum.GetNames<FirewallDirection>(), name =>
                Assert.NotEqual("missing", localization.GetOrFallback($"FirewallDirection{name}", "missing")));
            Assert.All(Enum.GetNames<FirewallAction>(), name =>
                Assert.NotEqual("missing", localization.GetOrFallback($"FirewallAction{name}", "missing")));
        }
        finally
        {
            localization.SetCulture(original);
        }
    }

    [Theory]
    [InlineData(
        "fr",
        "Le filtrage est activé. Les blocages enregistrés filtrent désormais le trafic sortant.",
        "La demande est terminée, mais aucun filtrage actif n'a été observé. Vérifiez l'état du pare-feu avant de vous fier aux blocages enregistrés.")]
    [InlineData(
        "es",
        "El filtrado está activado. Los bloqueos guardados ya filtran el tráfico saliente.",
        "La solicitud terminó, pero no se observó filtrado activo. Compruebe el estado del firewall antes de confiar en los bloqueos guardados.")]
    public void FirewallRuntimeTruthfulness_UsesCorrectFrenchAndSpanishWording(
        string culture,
        string expectedActive,
        string expectedNotActive)
    {
        var localization = LocalizationManager.Instance;
        var original = localization.CurrentCode;
        try
        {
            localization.SetCulture(culture);
            Assert.Equal(expectedActive, localization["FirewallEnforcementEnabled"]);
            Assert.Equal(expectedNotActive, localization["FirewallEnforcementNotActive"]);
        }
        finally
        {
            localization.SetCulture(original);
        }
    }

    [Theory]
    [InlineData(
        "en",
        "Turn off outbound filtering and lift every WinSight block? The machine returns to audit-only.",
        "Service endpoint reachable; audit-only. Policies are recorded but nothing is blocked.",
        "Service endpoint reachable and enforcing per-application policies.")]
    [InlineData(
        "fr",
        "Désactiver le filtrage et lever tous les blocages WinSight ? La machine repasse en audit seul.",
        "Point de service accessible, audit seul. Les politiques sont enregistrées mais rien n’est bloqué.",
        "Point de service accessible ; le filtrage par application est actif.")]
    [InlineData(
        "es",
        "¿Desactivar el filtrado y levantar todos los bloqueos de WinSight? La máquina vuelve a solo auditoría.",
        "Punto de servicio accesible, solo auditoría. Las políticas se registran pero no se bloquea nada.",
        "Punto de servicio accesible; el filtrado por aplicación está activo.")]
    public void FirewallTrustBoundaryText_UsesFilteringAndReachabilitySemantics(
        string culture,
        string expectedEmergencyConfirmation,
        string expectedAuditOnly,
        string expectedEnforcing)
    {
        var localization = LocalizationManager.Instance;
        var original = localization.CurrentCode;
        try
        {
            localization.SetCulture(culture);
            Assert.Equal(expectedEmergencyConfirmation, localization["FirewallEmergencyConfirm"]);
            Assert.Equal(expectedAuditOnly, localization["OutboundFirewallAuditOnly"]);
            Assert.Equal(expectedEnforcing, localization["OutboundFirewallEnforcing"]);
            Assert.DoesNotContain("installed", localization["OutboundFirewallAuditOnly"], StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("installé", localization["OutboundFirewallAuditOnly"], StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("instalado", localization["OutboundFirewallAuditOnly"], StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            localization.SetCulture(original);
        }
    }

    [Theory]
    [InlineData("en", "requested mode", "effective runtime state", "service registration", "LocalSystem", "degraded", "installation")]
    [InlineData("fr", "mode demandé", "état effectif", "enregistrement du service", "LocalSystem", "dégradé", "installation")]
    [InlineData("es", "modo solicitado", "estado efectivo", "registro del servicio", "LocalSystem", "degradado", "instalacion")]
    public void FirewallGuidance_DistinguishesDesiredRuntimeAndWindowsTrustChecks(
        string culture,
        string desired,
        string effective,
        string registration,
        string localSystem,
        string degraded,
        string installation)
    {
        var localization = LocalizationManager.Instance;
        var original = localization.CurrentCode;
        try
        {
            localization.SetCulture(culture);
            var description = localization["ToolOutboundFirewallDescription"];
            var guidance = localization["ToolOutboundFirewallGuidance"];
            var unavailable = localization["OutboundFirewallUnavailable"];

            Assert.Contains(desired, description, StringComparison.OrdinalIgnoreCase);
            Assert.Contains(effective, description, StringComparison.OrdinalIgnoreCase);
            Assert.Contains(registration, guidance, StringComparison.OrdinalIgnoreCase);
            Assert.Contains(localSystem, guidance, StringComparison.Ordinal);
            Assert.Contains(degraded, guidance, StringComparison.OrdinalIgnoreCase);
            var plainUnavailable = RemoveDiacritics(unavailable);
            Assert.Contains(installation, plainUnavailable, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("verif", plainUnavailable, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            localization.SetCulture(original);
        }
    }

    private static string RemoveDiacritics(string value) => string.Concat(
        value.Normalize(System.Text.NormalizationForm.FormD)
            .Where(character => System.Globalization.CharUnicodeInfo.GetUnicodeCategory(character)
                != System.Globalization.UnicodeCategory.NonSpacingMark));

    [Theory]
    [InlineData("en", "1 result shown · 1 needs attention", "2 results shown · 2 need attention")]
    [InlineData("fr", "1 résultat affiché · 1 à vérifier", "2 résultats affichés · 2 à vérifier")]
    [InlineData("es", "1 resultado mostrado · 1 requiere atención", "2 resultados mostrados · 2 requieren atención")]
    public void ResultSummary_UsesNaturalSingularAndPlural(
        string culture,
        string expectedSingular,
        string expectedPlural)
    {
        var localization = LocalizationManager.Instance;
        var original = localization.CurrentCode;
        try
        {
            localization.SetCulture(culture);
            Assert.Equal(expectedSingular, DashboardResultSummary.Format(localization, 1, 1));
            Assert.Equal(expectedPlural, DashboardResultSummary.Format(localization, 2, 2));
        }
        finally
        {
            localization.SetCulture(original);
        }
    }
}
