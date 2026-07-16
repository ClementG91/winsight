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
    [InlineData("en", "Service not installed", "Block")]
    [InlineData("fr", "Service non installé", "Bloquer")]
    [InlineData("es", "Servicio no instalado", "Bloquear")]
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
