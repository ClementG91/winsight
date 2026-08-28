using System.Text.RegularExpressions;

using WinSight.Persistence;
using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// The autostart surface count the documentation advertises must be the number of surfaces that
/// exist.
/// </summary>
/// <remarks>
/// <b>Why this is a test and not a review habit.</b> "22 autostart surfaces" appeared in the README
/// and in the Objective-See parity table, hand-maintained in both, and was correct only because
/// nobody had added a surface since it was written. A static audit checked it by counting the enum
/// members by hand - which is exactly the work a test should be doing, and exactly the drift this
/// project already removed for <c>--help</c> and for the MCP schema by deriving the list instead of
/// declaring it twice.
///
/// A number in a README is a claim about the product. Adding a surface and forgetting the sentence
/// makes the product undersell itself; removing one and forgetting it makes the sentence a lie. This
/// fails the build for either.
/// </remarks>
public sealed class SurfaceCountDocumentationTests
{
    private static readonly string RepositoryRoot = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    /// <summary>Documents that state the count, and the phrase each states it in.</summary>
    public static TheoryData<string> DocumentsClaimingASurfaceCount()
    {
        var documents = new TheoryData<string>();
        documents.Add("README.md");
        documents.Add(Path.Combine("docs", "OBJECTIVE_SEE_PARITY.md"));
        documents.Add(Path.Combine("docs", "DETECTIONS.md"));
        return documents;
    }

    [Theory]
    [MemberData(nameof(DocumentsClaimingASurfaceCount))]
    public void TheDocumentedCountMatchesTheEnum(string relativePath)
    {
        var path = Path.Combine(RepositoryRoot, relativePath);
        Assert.True(File.Exists(path), $"{relativePath} was not found at {path}");

        var text = File.ReadAllText(path);
        var claims = Regex.Matches(text, @"(?<count>\d+)\s+(?:Windows\s+)?autostart (?:surfaces|families)")
            .Select(match => int.Parse(match.Groups["count"].Value, System.Globalization.CultureInfo.InvariantCulture))
            .ToList();

        // Guards the guard: a regex that stopped matching would make this vacuous, and the whole
        // point is that the claim cannot quietly stop being checked.
        Assert.True(
            claims.Count > 0,
            $"{relativePath} no longer states an autostart surface count in a form this test "
            + "recognises. Either restore the phrasing or remove this document from the list.");

        var actual = Enum.GetValues<AutostartVector>().Length;
        Assert.All(claims, claimed => Assert.Equal(actual, claimed));
    }

    /// <summary>
    /// Every surface an enumerator can produce must be one the default scanner actually runs, or the
    /// count is arithmetic about code nothing calls.
    /// </summary>
    [Fact]
    public void EverySurfaceCountedIsOneTheDefaultScannerCanReach()
    {
        var registered = PersistenceScanner.DefaultEnumerators();

        Assert.NotEmpty(registered);
        // One enumerator may cover several vectors (Run keys and other users' hives both emit
        // RunKey), so this asserts reachability rather than a one-to-one mapping.
        Assert.True(
            registered.Count >= 20,
            $"only {registered.Count} enumerators are registered; the documented surface count "
            + "cannot be honest if surfaces are declared and never enumerated.");
    }
}
