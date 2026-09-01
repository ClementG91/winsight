using System.Globalization;
using System.Resources;

using WinSight.CodeIntegrity;
using WinSight.Reporting;
using Xunit;

namespace WinSight.Dashboard.Tests;

/// <summary>
/// Every protection the integrity triage can name, and every sub-case it can reach, must reach the
/// operator in the operator's language.
/// </summary>
/// <remarks>
/// <b>What this stops recurring.</b> The presenter handled Antivirus and Controlled Folder Access
/// and let the other five fall through to <c>item.Detail</c> - the English source string.
/// <c>integrity</c> is in the default scan, so a French operator read a title spelled
/// <c>test-signing</c> followed by an English sentence, on the one check that reframes every other
/// kernel finding. The resource files themselves were faultless: identical key sets across the three
/// languages. Nothing connected the triage's vocabulary to them, and nothing would have said so.
///
/// The states are enumerated by running the triage over machine states that reach every branch,
/// rather than from a list restated here - a hand-maintained copy is exactly the drift this exists
/// to catch.
/// </remarks>
[Collection(LocalizationCollection.Name)]
public sealed class IntegrityLocalizationTests
{
    private static readonly ResourceManager Resources = new(
        "WinSight.Dashboard.Localization.Strings",
        typeof(LocalizationManager).Assembly);

    [Fact]
    public void EveryProtectionTheTriageCanEmitHasATitleKey()
    {
        var keys = ReachableFindings()
            .Select(finding => DashboardFindingPresenter.IntegrityTitleKey(finding.Name))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        // The enumeration must not have quietly gone empty, or this test passes by finding nothing.
        Assert.Equal(7, keys.Length);
        Assert.DoesNotContain(keys, key => Resources.GetString(key, CultureInfo.InvariantCulture) is null);
    }

    [Fact]
    public void EverySubCaseTheTriageCanReachHasAnExplanationKey()
    {
        var keys = ReachableFindings()
            .Select(finding =>
                DashboardFindingPresenter.IntegrityDetailKey(finding.Name, finding.State))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        // A lower bound, not an equality: adding a sub-case should fail below, on its missing key,
        // with a message that names it - not here, on an arithmetic mismatch.
        Assert.True(keys.Length >= 19, $"only {keys.Length} sub-cases reached");
        Assert.DoesNotContain(keys, key => Resources.GetString(key, CultureInfo.InvariantCulture) is null);
    }

    /// <summary>
    /// The end-to-end path: a report item as the adapter writes it, presented in French, must be
    /// French - title and explanation both.
    /// </summary>
    [Theory]
    [InlineData("fr")]
    [InlineData("es")]
    public void TheFindingIsPresentedInTheOperatorsLanguage(string language)
    {
        var localization = LocalizationManager.Instance;
        var original = localization.CurrentCode;
        try
        {
            localization.SetCulture(language);
            var item = new ReportItem(
                Severity.Notable,
                "test-signing",
                "TEST SIGNING is enabled: this machine will load a driver signed by anyone.",
                new Dictionary<string, string?>
                {
                    ["protection"] = "test-signing",
                    ["concern"] = "Weakened",
                    ["state"] = "on",
                });

            var presented = DashboardFindingPresenter.Present("integrity", item, localization);

            Assert.NotEqual(item.Title, presented.Title);
            Assert.NotEqual(item.Detail, presented.Detail);
            Assert.DoesNotContain("test-signing", presented.Title, StringComparison.Ordinal);
        }
        finally
        {
            localization.SetCulture(original);
        }
    }

    /// <summary>
    /// A finding from a future version, carrying a state this build has no key for, must degrade to
    /// the English source text rather than to a resource key.
    /// </summary>
    [Fact]
    public void AnUnknownSubCaseFallsBackToTheSourceText()
    {
        var item = new ReportItem(
            Severity.Info,
            "secure-boot",
            "Some state this build has never heard of.",
            new Dictionary<string, string?>
            {
                ["protection"] = "secure-boot",
                ["state"] = "invented-later",
            });

        var presented = DashboardFindingPresenter.Present(
            "integrity", item, LocalizationManager.Instance);

        Assert.Equal(item.Detail, presented.Detail);
    }

    /// <summary>The key derivation is part of the contract between the triage and the resources.</summary>
    [Theory]
    [InlineData("secure-boot", "IntegrityProtectionSecureBoot")]
    [InlineData("driver-signature-enforcement", "IntegrityProtectionDriverSignatureEnforcement")]
    [InlineData("user-mode-code-integrity", "IntegrityProtectionUserModeCodeIntegrity")]
    public void TheTitleKeyIsDerivedFromTheContractIdentifier(string protection, string expected) =>
        Assert.Equal(expected, DashboardFindingPresenter.IntegrityTitleKey(protection));

    [Theory]
    [InlineData("memory-integrity", "audit", "IntegrityStateMemoryIntegrityAudit")]
    [InlineData("kernel-debugger", "attached", "IntegrityStateKernelDebuggerAttached")]
    public void TheDetailKeyIsDerivedFromTheProtectionAndItsState(
        string protection, string state, string expected) =>
        Assert.Equal(expected, DashboardFindingPresenter.IntegrityDetailKey(protection, state));

    /// <summary>
    /// Every finding the triage can produce, by driving it over machine states that reach each
    /// branch: the kernel silent, then every combination of the options the triage reads, crossed
    /// with the three readings of Secure Boot and of the kernel debugger.
    /// </summary>
    private static List<IntegrityFinding> ReachableFindings()
    {
        CodeIntegrityOptions[] combinations =
        [
            CodeIntegrityOptions.None,
            CodeIntegrityOptions.Enabled,
            CodeIntegrityOptions.TestSign,
            CodeIntegrityOptions.UserModeEnabled,
            CodeIntegrityOptions.DebugModeEnabled,
            CodeIntegrityOptions.HypervisorEnforced,
            CodeIntegrityOptions.HypervisorEnforced | CodeIntegrityOptions.HypervisorAuditMode,
            CodeIntegrityOptions.HypervisorEnforced | CodeIntegrityOptions.HypervisorStrictMode,
        ];
        ProtectionReading[] readings =
            [ProtectionReading.On, ProtectionReading.Off, ProtectionReading.Unknown];

        var findings = new List<IntegrityFinding>(CodeIntegrityTriage.Evaluate(
            new CodeIntegrityState(
                CodeIntegrityOptions.None, 0, OptionsRead: false,
                ProtectionReading.Unknown, ProtectionReading.Unknown)));
        foreach (var options in combinations)
        {
            foreach (var secureBoot in readings)
            {
                foreach (var debugger in readings)
                {
                    findings.AddRange(CodeIntegrityTriage.Evaluate(new CodeIntegrityState(
                        options, (uint)options, OptionsRead: true, secureBoot, debugger)));
                }
            }
        }
        return findings;
    }
}
