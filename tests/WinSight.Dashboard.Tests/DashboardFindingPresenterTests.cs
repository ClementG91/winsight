using System.Collections;
using System.Globalization;
using System.Resources;
using WinSight.Reporting;
using Xunit;

namespace WinSight.Dashboard.Tests;

[Collection(LocalizationCollection.Name)]
public sealed class DashboardFindingPresenterTests
{
    [Theory]
    [InlineData("en", "Service or driver/WinSetupMon", "File missing")]
    [InlineData("fr", "Service ou pilote/WinSetupMon", "Fichier absent")]
    [InlineData("es", "Servicio o controlador/WinSetupMon", "Falta el archivo")]
    public void PersistencePresentation_LocalizesVectorAndStatus(
        string culture,
        string expectedTitle,
        string expectedStatus)
    {
        WithCulture(culture, text =>
        {
            var item = Item(Severity.Notable, new()
            {
                ["vector"] = "Service",
                ["name"] = "WinSetupMon",
                ["expectedImage"] = @"C:\Windows\System32\drivers\WinSetupMon.sys",
                ["status"] = "FileMissing",
            });

            var result = DashboardFindingPresenter.Present("persistence", item, text);

            Assert.Equal(expectedTitle, result.Title);
            Assert.Contains(expectedStatus, result.Detail);
            Assert.Contains(@"C:\Windows\System32\drivers\WinSetupMon.sys", result.Detail);
        });
    }

    [Theory]
    [InlineData("en", "Webcam/Browser", "In use now")]
    [InlineData("fr", "Caméra/Browser", "Utilisé actuellement")]
    [InlineData("es", "Cámara/Browser", "En uso ahora")]
    public void CameraPresentation_LocalizesSemanticsButPreservesApp(
        string culture,
        string expectedTitle,
        string expectedDetail)
    {
        WithCulture(culture, text =>
        {
            var item = Item(Severity.Notable, new()
            {
                ["kind"] = "webcam",
                ["app"] = "Browser",
                ["active"] = "True",
            });

            var result = DashboardFindingPresenter.Present("camera-mic", item, text);

            Assert.Equal(expectedTitle, result.Title);
            Assert.Equal(expectedDetail, result.Detail);
        });
    }

    [Theory]
    [InlineData("en", "Redirects a hostname")]
    [InlineData("fr", "Redirige un nom d’hôte")]
    [InlineData("es", "Redirige un nombre de host")]
    public void HostPresentation_LocalizesReason(string culture, string expected)
    {
        WithCulture(culture, text =>
        {
            var item = Item(Severity.Notable, new() { ["isSink"] = "False" });
            Assert.StartsWith(expected, DashboardFindingPresenter.Present("hosts", item, text).Detail);
        });
    }

    [Theory]
    [InlineData("en", "Inbound/Block, Rule")]
    [InlineData("fr", "Entrant/Bloquer, Rule")]
    [InlineData("es", "Entrante/Bloquear, Rule")]
    public void FirewallPresentation_LocalizesEnumsAndPreservesRuleName(string culture, string expected)
    {
        WithCulture(culture, text =>
        {
            var item = Item(Severity.Info, new()
            {
                ["direction"] = "Inbound",
                ["action"] = "Block",
                ["name"] = "Rule",
                ["program"] = @"C:\Program Files\App\app.exe",
            });

            var result = DashboardFindingPresenter.Present("firewall", item, text);

            Assert.Equal(expected, result.Title);
            Assert.Equal(@"C:\Program Files\App\app.exe", result.Detail);
        });
    }

    [Theory]
    [InlineData("en", "Firewall service unavailable", "Block")]
    [InlineData("fr", "Service de pare-feu indisponible", "Bloquer")]
    [InlineData("es", "Servicio de firewall no disponible", "Bloquear")]
    public void OutboundFirewallPresentation_LocalizesStatusAndAction(
        string culture,
        string expectedUnavailable,
        string expectedBlock)
    {
        WithCulture(culture, text =>
        {
            var status = Item(Severity.Info, new() { ["kind"] = "status", ["available"] = "False" });
            var statusResult = DashboardFindingPresenter.Present("outbound-firewall", status, text);
            Assert.StartsWith(expectedUnavailable, statusResult.Detail);

            var policy = Item(Severity.Info, new()
            {
                ["kind"] = "policy",
                ["path"] = @"C:\apps\a.exe",
                ["action"] = "Block",
            });
            var policyResult = DashboardFindingPresenter.Present("outbound-firewall", policy, text);
            Assert.Equal(@"C:\apps\a.exe", policyResult.Title);
            Assert.Equal(expectedBlock, policyResult.Detail);
        });
    }

    [Theory]
    [InlineData("en", "disabled")]
    [InlineData("fr", "désactiv")]
    [InlineData("es", "desactiv")]
    public void OutboundFirewallPresentation_DisabledPolicyIsExplicitAndLocalized(
        string culture,
        string expectedDisabledStem)
    {
        WithCulture(culture, text =>
        {
            var disabled = DashboardFindingPresenter.Present(
                "outbound-firewall",
                Item(Severity.Info, new()
                {
                    ["kind"] = "policy",
                    ["path"] = @"C:\apps\disabled.exe",
                    ["action"] = "Block",
                    ["enabled"] = "False",
                }),
                text);
            var enabled = DashboardFindingPresenter.Present(
                "outbound-firewall",
                Item(Severity.Info, new()
                {
                    ["kind"] = "policy",
                    ["path"] = @"C:\apps\disabled.exe",
                    ["action"] = "Block",
                    ["enabled"] = "True",
                }),
                text);

            Assert.NotEqual(enabled.Detail, disabled.Detail);
            Assert.Contains(expectedDisabledStem, disabled.Detail, StringComparison.OrdinalIgnoreCase);
        });
    }

    [Theory]
    [InlineData("en", "enforcement is degraded")]
    [InlineData("fr", "filtrage dégradé")]
    [InlineData("es", "filtrado degradado")]
    public void OutboundFirewallPresentation_DegradedRuntimeIsLocalizedAndNeverClaimedActive(
        string culture, string expectedDetail)
    {
        WithCulture(culture, text =>
        {
            var result = DashboardFindingPresenter.Present(
                "outbound-firewall",
                Item(Severity.Info, new()
                {
                    ["kind"] = "status",
                    ["available"] = "True",
                    ["mode"] = "Enforcement",
                    ["enforcement"] = "False",
                    ["effectiveState"] = "Degraded",
                }),
                text);

            Assert.Contains(expectedDetail, result.Detail, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("enforcement is active", result.Detail, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("filtrage actif", result.Detail, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("filtrado activo", result.Detail, StringComparison.OrdinalIgnoreCase);
        });
    }

    [Theory]
    [InlineData("en", "Service endpoint reachable and enforcing")]
    [InlineData("fr", "Point de service accessible ; le filtrage")]
    [InlineData("es", "Punto de servicio accesible; el filtrado")]
    public void OutboundFirewallPresentation_OnlyObservedActiveRuntimeUsesTheLocalizedActiveMessage(
        string culture, string expectedDetail)
    {
        WithCulture(culture, text =>
        {
            var active = DashboardFindingPresenter.Present(
                "outbound-firewall",
                Item(Severity.Info, new()
                {
                    ["kind"] = "status",
                    ["available"] = "True",
                    ["mode"] = "Enforcement",
                    ["enforcement"] = "True",
                    ["effectiveState"] = "Active",
                }),
                text);
            var desiredOnly = DashboardFindingPresenter.Present(
                "outbound-firewall",
                Item(Severity.Info, new()
                {
                    ["kind"] = "status",
                    ["available"] = "True",
                    ["mode"] = "Enforcement",
                    ["enforcement"] = "False",
                    ["effectiveState"] = "AuditOnly",
                }),
                text);

            Assert.Contains(expectedDetail, active.Detail, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(expectedDetail, desiredOnly.Detail, StringComparison.OrdinalIgnoreCase);
        });
    }

    [Theory]
    [InlineData("en", "not installed")]
    [InlineData("fr", "non installé")]
    [InlineData("es", "no instalado")]
    public void OutboundFirewallPresentation_UnavailablePipeDoesNotInventInstallationState(
        string culture, string forbiddenPhrase)
    {
        WithCulture(culture, text =>
        {
            var result = DashboardFindingPresenter.Present(
                "outbound-firewall",
                Item(Severity.Info, new() { ["kind"] = "status", ["available"] = "False" }),
                text);

            Assert.DoesNotContain(forbiddenPhrase, result.Detail, StringComparison.OrdinalIgnoreCase);
        });
    }

    // Regression, found on a real machine: a pending row has no "available" field, so an earlier
    // version fell through to the status branch and rendered every one of them as "the service is
    // not installed" while the service was running. The UI stated the opposite of the truth about
    // whether the machine was protected.
    [Theory]
    [InlineData("en")]
    [InlineData("fr")]
    [InlineData("es")]
    public void OutboundFirewallPresentation_PendingRow_NeverSpeaksAsAStatusRow(string culture)
    {
        WithCulture(culture, text =>
        {
            var unavailable = DashboardFindingPresenter.Present(
                "outbound-firewall",
                Item(Severity.Info, new() { ["kind"] = "status", ["available"] = "False" }),
                text).Detail;

            var pending = DashboardFindingPresenter.Present(
                "outbound-firewall",
                Item(Severity.Notable, new()
                {
                    ["kind"] = "pending",
                    ["path"] = @"C:\jamaisvu\appinconnue.exe",
                    ["remote"] = "93.184.216.34:443",
                    ["observations"] = "3",
                }),
                text);

            Assert.Equal(@"C:\jamaisvu\appinconnue.exe", pending.Title);
            Assert.NotEqual(unavailable, pending.Detail);
            Assert.Contains("93.184.216.34:443", pending.Detail, StringComparison.Ordinal);
            Assert.Contains("3", pending.Detail, StringComparison.Ordinal);
        });
    }

    // A kind this presenter does not know must fall back to the report's own values. Speaking as a
    // status row is how the previous defect turned a new row type into a false claim.
    [Fact]
    public void OutboundFirewallPresentation_UnknownKind_FallsBackToTheReportsOwnValues()
    {
        WithCulture("en", text =>
        {
            var result = DashboardFindingPresenter.Present(
                "outbound-firewall",
                Item(Severity.Info, new() { ["kind"] = "something-new" }),
                text);

            Assert.Equal("raw-title", result.Title);
            Assert.Equal("raw-detail", result.Detail);
        });
    }

    [Theory]
    [InlineData("en")]
    [InlineData("fr")]
    [InlineData("es")]
    public void AntivirusPresentation_LocalizesEveryConcernFromIndexedEvidence(string culture)
    {
        WithCulture(culture, text =>
        {
            const string product = "Produit Ω;Vendor";
            var cases = new[]
            {
                (
                    Concern: "Protected",
                    Item: AntivirusItem("Protected", (product, "On", "UpToDate")),
                    Expected: text.Format("AntivirusProtected", product)),
                (
                    Concern: "SignaturesOutOfDate",
                    Item: AntivirusItem("SignaturesOutOfDate", (product, "On", "OutOfDate")),
                    Expected: text.Format("AntivirusSignaturesOutOfDate", product)),
                (
                    Concern: "SignatureStatusUnknown",
                    Item: AntivirusItem("SignatureStatusUnknown", (product, "On", "Unknown")),
                    Expected: text.Format("AntivirusSignatureStatusUnknown", product)),
                (
                    Concern: "ActivityStatusUnknown",
                    Item: AntivirusItem("ActivityStatusUnknown", (product, "Unknown", "OutOfDate")),
                    Expected: text.Format("AntivirusActivityStatusUnknown", product)),
                (
                    Concern: "NoActiveAntiVirus",
                    Item: AntivirusItem("NoActiveAntiVirus", (product, "Snoozed", "UpToDate")),
                    Expected: text.Format(
                        "AntivirusNoActive",
                        text.Format("AntivirusStateGroup", text["AntivirusStateSnoozed"], product))),
                (
                    Concern: "NoAntiVirusRegistered",
                    Item: AntivirusItem("NoAntiVirusRegistered"),
                    Expected: text["AntivirusNoneRegistered"]),
                (
                    Concern: "Unavailable",
                    Item: AntivirusItem("Unavailable"),
                    Expected: text["AntivirusUnavailable"]),
            };

            foreach (var sample in cases)
            {
                var result = DashboardFindingPresenter.Present("integrity", sample.Item, text);

                Assert.Equal(text["AntivirusProtectionTitle"], result.Title);
                Assert.Equal(sample.Expected, result.Detail);
                Assert.DoesNotContain("APPLICATION ENGLISH PROSE", result.Detail, StringComparison.Ordinal);
                if (sample.Item.Fields["registeredAntivirusCount"] != "0")
                {
                    Assert.Contains(product, result.Detail, StringComparison.Ordinal);
                }
            }
        });
    }

    [Theory]
    [InlineData("en")]
    [InlineData("fr")]
    [InlineData("es")]
    public void ControlledFolderAccessPresentation_LocalizesEveryNonDefenderConcern(string culture)
    {
        WithCulture(culture, text =>
        {
            var cases = new[]
            {
                (Concern: "Off", Expected: text["CfaOff"]),
                (Concern: "AuditOnly", Expected: text["CfaAuditOnly"]),
                (Concern: "BlockDiskModificationOnly", Expected: text["CfaBlockDiskModificationOnly"]),
                (Concern: "AuditDiskModificationOnly", Expected: text["CfaAuditDiskModificationOnly"]),
                (Concern: "Protecting", Expected: text["CfaProtecting"]),
                (Concern: "RuntimeRequirementsNotMet", Expected: text["CfaRuntimeRequirementsNotMet"]),
                (Concern: "Unavailable", Expected: text["CfaUnavailable"]),
            };

            foreach (var sample in cases)
            {
                var result = DashboardFindingPresenter.Present(
                    "integrity",
                    CfaItem(sample.Concern),
                    text);

                Assert.Equal(text["CfaTitle"], result.Title);
                Assert.Equal(sample.Expected, result.Detail);
                Assert.DoesNotContain("APPLICATION ENGLISH PROSE", result.Detail, StringComparison.Ordinal);
            }

            var unknown = DashboardFindingPresenter.Present(
                "integrity",
                CfaItem("UnknownMode", ("rawStateValue", "57")),
                text);
            Assert.Equal(text.Format("CfaUnknownMode", "57"), unknown.Detail);
            Assert.DoesNotContain("APPLICATION ENGLISH PROSE", unknown.Detail, StringComparison.Ordinal);
        });
    }

    [Theory]
    [InlineData("en")]
    [InlineData("fr")]
    [InlineData("es")]
    public void DefenderNotRunningPresentation_LocalizesEveryAntivirusEvidenceBranch(string culture)
    {
        WithCulture(culture, text =>
        {
            const string product = "Produit Ω;Vendor";
            var cases = new[]
            {
                (
                    Item: CfaItem(
                        "DefenderNotRunning",
                        ("antivirusConcern", "Protected"),
                        ("protectedThirdPartyAntivirus", product)),
                    Expected: text.Format("CfaDefenderNotRunningProtectedThirdParty", product)),
                (
                    Item: CfaItem("DefenderNotRunning", ("antivirusConcern", "Unavailable")),
                    Expected: text["CfaDefenderNotRunningAvUnavailable"]),
                (
                    Item: CfaItem(
                        "DefenderNotRunning",
                        ("antivirusConcern", "ActivityStatusUnknown"),
                        ("activityUnknownAntivirus", product)),
                    Expected: text.Format("CfaDefenderNotRunningActivityUnknown", product)),
                (
                    Item: CfaItem(
                        "DefenderNotRunning",
                        ("antivirusConcern", "SignatureStatusUnknown"),
                        ("onAntivirus", product)),
                    Expected: text.Format("CfaDefenderNotRunningSignatureUnknown", product)),
                (
                    Item: CfaItem(
                        "DefenderNotRunning",
                        ("antivirusConcern", "SignaturesOutOfDate"),
                        ("onAntivirus", product)),
                    Expected: text.Format("CfaDefenderNotRunningSignaturesOutOfDate", product)),
                (
                    Item: CfaItem("DefenderNotRunning", ("antivirusConcern", "Protected")),
                    Expected: text["CfaDefenderNotRunningInconsistent"]),
                (
                    Item: CfaItem("DefenderNotRunning", ("antivirusConcern", "NoActiveAntiVirus")),
                    Expected: text["CfaDefenderNotRunningNoOnAntivirus"]),
            };

            foreach (var sample in cases)
            {
                var result = DashboardFindingPresenter.Present("integrity", sample.Item, text);

                Assert.Equal(text["CfaTitle"], result.Title);
                Assert.Equal(sample.Expected, result.Detail);
                Assert.DoesNotContain("APPLICATION ENGLISH PROSE", result.Detail, StringComparison.Ordinal);
                if (sample.Expected.Contains(product, StringComparison.Ordinal))
                {
                    Assert.Contains(product, result.Detail, StringComparison.Ordinal);
                }
            }
        });
    }

    [Fact]
    public void AntivirusAndCfaResourceKeys_HaveExactEnglishFrenchSpanishParity()
    {
        var resources = new ResourceManager(
            "WinSight.Dashboard.Localization.Strings",
            typeof(LocalizationManager).Assembly);
        var sets = new[]
        {
            resources.GetResourceSet(CultureInfo.InvariantCulture, true, false),
            resources.GetResourceSet(CultureInfo.GetCultureInfo("fr"), true, false),
            resources.GetResourceSet(CultureInfo.GetCultureInfo("es"), true, false),
        };
        Assert.All(sets, Assert.NotNull);

        var relevantKeys = sets
            .Select(set => set!.Cast<DictionaryEntry>()
                .Select(entry => Assert.IsType<string>(entry.Key))
                .Where(key =>
                    key.StartsWith("Antivirus", StringComparison.Ordinal)
                    || key.StartsWith("Cfa", StringComparison.Ordinal))
                .ToHashSet(StringComparer.Ordinal))
            .ToArray();

        Assert.NotEmpty(relevantKeys[0]);
        Assert.True(relevantKeys[0].SetEquals(relevantKeys[1]));
        Assert.True(relevantKeys[0].SetEquals(relevantKeys[2]));
        foreach (var key in relevantKeys[0].Where(key => key != "AntivirusStateGroup"))
        {
            var english = sets[0]!.GetString(key);
            Assert.NotEqual(english, sets[1]!.GetString(key));
            Assert.NotEqual(english, sets[2]!.GetString(key));
        }
    }

    [Theory]
    [InlineData("en")]
    [InlineData("fr")]
    [InlineData("es")]
    public void EveryStructuredTool_HasAResourceBackedPresentation(string culture)
    {
        WithCulture(culture, text =>
        {
            var samples = new Dictionary<string, ReportItem>
            {
                ["processes"] = Item(Severity.Info, new() { ["name"] = "app", ["pid"] = "7" }),
                ["modules"] = Item(Severity.Notable, new() { ["process"] = "app", ["pid"] = "7", ["module"] = "x.dll" }),
                ["certificates"] = Item(Severity.Notable, new() { ["hasPrivateKey"] = "True" }),
                ["extensions"] = Item(Severity.Info, new()),
                ["connections"] = Item(Severity.Info, new() { ["process"] = "app", ["pid"] = "7", ["state"] = "ESTABLISHED" }),
                ["outbound-firewall"] = Item(Severity.Info, new() { ["kind"] = "status", ["available"] = "False" }),
            };

            foreach (var sample in samples)
            {
                var result = DashboardFindingPresenter.Present(sample.Key, sample.Value, text);
                Assert.False(string.IsNullOrWhiteSpace(result.Title));
                Assert.False(string.IsNullOrWhiteSpace(result.Detail));
                Assert.DoesNotContain("[UnknownValue]", result.Detail, StringComparison.Ordinal);
            }
        });
    }

    private static ReportItem Item(Severity severity, Dictionary<string, string?> fields) =>
        new(severity, "raw-title", "raw-detail", fields);

    private static ReportItem AntivirusItem(
        string concern,
        params (string Name, string Activity, string Signature)[] products)
    {
        var fields = new Dictionary<string, string?>
        {
            ["protection"] = "Antivirus",
            ["concern"] = concern,
            ["registeredAntivirusCount"] = products.Length.ToString(CultureInfo.InvariantCulture),
        };
        for (var index = 0; index < products.Length; index++)
        {
            var prefix = $"antivirusProduct.{index}.";
            fields[$"{prefix}name"] = products[index].Name;
            fields[$"{prefix}activity"] = products[index].Activity;
            fields[$"{prefix}signature"] = products[index].Signature;
        }
        return new ReportItem(
            Severity.Notable,
            "APPLICATION ENGLISH PROSE TITLE",
            "APPLICATION ENGLISH PROSE DETAIL",
            fields);
    }

    private static ReportItem CfaItem(
        string concern,
        params (string Key, string? Value)[] additionalFields)
    {
        var fields = new Dictionary<string, string?>
        {
            ["protection"] = "Controlled Folder Access",
            ["concern"] = concern,
        };
        foreach (var (key, value) in additionalFields)
        {
            fields[key] = value;
        }
        return new ReportItem(
            Severity.Notable,
            "APPLICATION ENGLISH PROSE TITLE",
            "APPLICATION ENGLISH PROSE DETAIL",
            fields);
    }

    private static void WithCulture(string culture, Action<LocalizationManager> assertion)
    {
        var text = LocalizationManager.Instance;
        var original = text.CurrentCode;
        try
        {
            text.SetCulture(culture);
            assertion(text);
        }
        finally
        {
            text.SetCulture(original);
        }
    }
}
