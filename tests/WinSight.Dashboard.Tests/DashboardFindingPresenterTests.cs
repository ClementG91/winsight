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
