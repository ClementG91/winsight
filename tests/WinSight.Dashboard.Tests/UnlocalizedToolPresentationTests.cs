using WinSight.Reporting;
using Xunit;

namespace WinSight.Dashboard.Tests;

/// <summary>
/// The six tools that once rendered raw English into the French and Spanish dashboards.
/// </summary>
/// <remarks>
/// <b>What went wrong the first time.</b> Six tools had no presenter arm, so the dispatch fell
/// through to <c>item.Detail</c> - the report's own English sentence - and a French or Spanish
/// operator read English. Among them was the strongest sentence the product produces: that a driver
/// is unsigned and can see every keystroke. The arms were written to fix that and then never
/// executed by a test, so the fix was unverified in every language it was written for.
///
/// <b>Why the assertion is "the three differ" rather than a hardcoded translation.</b> The defect
/// has a shape: a tool that falls back to <c>item.Detail</c> renders <i>identically</i> in all three
/// languages, because the fallback is the same English string every time. Comparing the three
/// renderings catches exactly that, and catches it again for any arm added later, without pinning a
/// translator's wording in a test file where it would have to be edited every time a sentence is
/// improved. The wording itself is already pinned by the resource-parity tests.
/// </remarks>
[Collection(LocalizationCollection.Name)]
public sealed class UnlocalizedToolPresentationTests
{
    /// <summary>One representative finding per tool, keyed by the tool name.</summary>
    private static readonly Dictionary<string, Dictionary<string, string?>> Arms = new()
    {
        {
            "input",
            new()
            {
                ["name"] = "kbdhook.sys",
                ["signature"] = "Unsigned",
                ["concern"] = "Untrusted",
                ["image"] = @"C:\Windows\System32\drivers\kbdhook.sys",
            }
        },
        {
            "drivers",
            new()
            {
                ["name"] = "vulndrv.sys",
                ["signature"] = "SignedUntrusted",
                ["concern"] = "Untrusted",
                ["image"] = @"C:\Windows\System32\drivers\vulndrv.sys",
            }
        },
        {
            "hijack",
            new()
            {
                ["kind"] = "PhantomImport",
                ["subject"] = "wlbsctrl.dll",
                ["exposure"] = "Exploitable",
                ["actionablePath"] = @"C:\Program Files\Vendor",
            }
        },
        {
            "presence",
            new()
            {
                ["cause"] = "PhysicalInput",
                ["wokeUtc"] = "2026-08-28T22:14:05.0000000+00:00",
                ["source"] = "HID Keyboard Device",
            }
        },
        {
            "dns",
            new()
            {
                ["name"] = "telemetry.example.invalid",
                ["type"] = "A",
                ["data"] = "203.0.113.7",
                ["local"] = "true",
            }
        },
        {
            "alerts",
            new()
            {
                ["source"] = "Ransomware",
                ["kind"] = "CanaryTouched",
                ["time"] = "2026-08-28T22:14:05.0000000+00:00",
                ["detail"] = "decoy rewritten",
            }
        },
    };

    public static TheoryData<string, Dictionary<string, string?>> LocalizedArms()
    {
        var data = new TheoryData<string, Dictionary<string, string?>>();
        foreach (var (tool, fields) in Arms)
        {
            data.Add(tool, fields);
        }
        return data;
    }

    /// <summary>
    /// Each of the six renders differently in English, French and Spanish.
    /// </summary>
    /// <remarks>
    /// An arm that fell back to <c>item.Detail</c> would produce one identical English string in all
    /// three, which is the regression these arms exist to prevent.
    /// </remarks>
    [Theory]
    [MemberData(nameof(LocalizedArms))]
    public void EachToolRendersDifferentlyInEachLanguage(
        string tool, Dictionary<string, string?> fields)
    {
        var english = Render("en", tool, fields);
        var french = Render("fr", tool, fields);
        var spanish = Render("es", tool, fields);

        Assert.NotEqual(english, french);
        Assert.NotEqual(english, spanish);
        Assert.NotEqual(french, spanish);
    }

    /// <summary>
    /// None of the six leaks the report's raw English detail into a localized dashboard.
    /// </summary>
    /// <remarks>
    /// The distinct-rendering test above proves an arm ran; this proves what it produced does not
    /// still carry the untranslated sentence. An arm that localized its title and then appended
    /// <c>item.Detail</c> would satisfy the first test and still show English prose.
    /// </remarks>
    [Theory]
    [MemberData(nameof(LocalizedArms))]
    public void NoToolLeaksTheRawEnglishDetail(string tool, Dictionary<string, string?> fields)
    {
        foreach (var culture in new[] { "fr", "es" })
        {
            var rendered = Render(culture, tool, fields);

            Assert.DoesNotContain("raw-detail", rendered, StringComparison.Ordinal);
            Assert.DoesNotContain("raw-title", rendered, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// The machine-supplied half of a finding survives translation.
    /// </summary>
    /// <remarks>
    /// Localizing by discarding is the failure mode that hides behind a passing translation test:
    /// the operator gets a fluent French sentence and loses the file name, the address or the device
    /// that told them which machine and which artefact this is about. Each of these values is chosen
    /// by whoever is being investigated, so it is never translated - it is carried through.
    /// </remarks>
    [Theory]
    [InlineData("input", "kbdhook.sys")]
    [InlineData("drivers", "vulndrv.sys")]
    [InlineData("hijack", "wlbsctrl.dll")]
    [InlineData("presence", "HID Keyboard Device")]
    [InlineData("dns", "telemetry.example.invalid")]
    [InlineData("alerts", "Ransomware")]
    public void TheMachineSuppliedValueSurvivesTranslation(string tool, string expected)
    {
        var fields = Arms[tool];

        foreach (var culture in new[] { "en", "fr", "es" })
        {
            Assert.Contains(expected, Render(culture, tool, fields), StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// A tool with no presenter arm still renders, rather than throwing on the operator's dashboard.
    /// </summary>
    [Fact]
    public void AnUnknownToolFallsBackToTheReportsOwnWords()
    {
        var presentation = Present("en", "no-such-tool", []);

        Assert.Equal("raw-title", presentation.Title);
        Assert.Equal("raw-detail", presentation.Detail);
    }

    private static string Render(string culture, string tool, Dictionary<string, string?> fields)
    {
        var presentation = Present(culture, tool, fields);
        return $"{presentation.Title}\u001f{presentation.Detail}";
    }

    private static FindingPresentation Present(
        string culture, string tool, Dictionary<string, string?> fields)
    {
        var text = LocalizationManager.Instance;
        var original = text.CurrentCode;
        try
        {
            text.SetCulture(culture);
            return DashboardFindingPresenter.Present(
                tool,
                new ReportItem(Severity.Notable, "raw-title", "raw-detail", fields),
                text);
        }
        finally
        {
            text.SetCulture(original);
        }
    }
}
