using WinSight.Application;
using WinSight.Attribution;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// Why a detection carries no author — the sentence that turns a silent absence into an answer.
/// </summary>
/// <remarks>
/// Three states hide behind a nameless alert and they call for three different responses: nothing was
/// watching, nothing <i>could</i> watch because the process is unelevated, or something was watching
/// and genuinely saw nothing. <see cref="AttributionHealth"/> was built to draw exactly those
/// distinctions and, until this, was read by nothing outside its own tests — so no operator, journal
/// or MCP client ever saw any of them.
/// </remarks>
public sealed class AttributionNoteTests
{
    private static readonly WriteObservation Author =
        new(DateTimeOffset.UnixEpoch, 8121, @"C:\Temp\x.exe", @"HKCU\...\Run", PathIsExact: true);

    private static AttributionHealth Health(bool running, bool refused) =>
        new(running, Attributed: 0, UnknownProcess: 0, UnannouncedKey: 0,
            UntranslatablePath: 0, Refused: refused);

    // ---- The three states are actually distinguishable ---------------------------------------

    [Fact]
    public void NoHostAtAllReadsAsNotRunning()
        => Assert.Equal("attribution not running", AttributionNote.WhyNoAuthor(null));

    [Fact]
    public void ARefusedSessionSaysElevationWouldHaveNamedTheWriter()
        => Assert.Equal(
            "attribution needs Administrator",
            AttributionNote.WhyNoAuthor(Health(running: false, refused: true)));

    [Fact]
    public void AWatchingSessionThatSawNothingSaysSo()
        => Assert.Equal(
            "attribution watching, no matching write seen",
            AttributionNote.WhyNoAuthor(Health(running: true, refused: false)));

    [Fact]
    public void AStoppedSessionIsNotTheSameAsOneThatNeverStarted()
        => Assert.Equal(
            "attribution stopped",
            AttributionNote.WhyNoAuthor(Health(running: false, refused: false)));

    /// <summary>
    /// The four answers must all differ, or the type is decorative.
    /// </summary>
    /// <remarks>
    /// This is the assertion that would have failed on the previous design, where every one of these
    /// produced the same empty string. Without it, a refactor that collapsed two states back into one
    /// would leave every other test in this file passing.
    /// </remarks>
    [Fact]
    public void EveryStateProducesADifferentAnswer()
    {
        string[] answers =
        [
            AttributionNote.WhyNoAuthor(null),
            AttributionNote.WhyNoAuthor(Health(running: false, refused: true)),
            AttributionNote.WhyNoAuthor(Health(running: true, refused: false)),
            AttributionNote.WhyNoAuthor(Health(running: false, refused: false)),
        ];

        Assert.Equal(answers.Length, answers.Distinct(StringComparer.Ordinal).Count());
        Assert.All(answers, answer => Assert.False(string.IsNullOrWhiteSpace(answer)));
    }

    // ---- Rendering ---------------------------------------------------------------------------

    [Fact]
    public void AKnownAuthorIsNamedAndCarriesNoCaveat()
    {
        var detail = AttributionNote.Describe("RunKey — evil.exe", Author, Health(true, false));

        Assert.Contains(@"written by C:\Temp\x.exe (pid 8121)", detail, StringComparison.Ordinal);
        Assert.DoesNotContain("author unknown", detail, StringComparison.Ordinal);
    }

    [Fact]
    public void AnAbsentAuthorAlwaysCarriesItsReason()
    {
        var detail = AttributionNote.Describe("RunKey — evil.exe", null, null);

        Assert.Contains("author unknown (attribution not running)", detail, StringComparison.Ordinal);
        // The detection itself must survive intact: the caveat is an addition, never a replacement.
        Assert.StartsWith("RunKey — evil.exe", detail, StringComparison.Ordinal);
    }

    [Fact]
    public void ABareNameAuthorIsNamedButNotPresentedAsALocatedFile()
    {
        var bareName = Author with { ExecutablePath = "powershell.exe", PathIsExact = false };

        var detail = AttributionNote.Describe("RunKey — evil.exe", bareName, Health(true, false));

        Assert.Contains("powershell.exe", detail, StringComparison.Ordinal);
        Assert.Contains("full path unknown", detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// Both monitors must produce the same sentence for the same situation.
    /// </summary>
    /// <remarks>
    /// The persistence and ransomware presenters each had their own copy of this rendering, and a
    /// security record whose wording depends on which code path reached it is one you have to read
    /// twice. They now share the helper; this pins that they still agree.
    /// </remarks>
    [Fact]
    public void BothMonitorsExplainAnAbsentAuthorIdentically()
    {
        var refused = Health(running: false, refused: true);
        var expected = $"author unknown ({AttributionNote.WhyNoAuthor(refused)})";

        var ransomware = RansomwarePresenter.AlertDetail(
            WinSight.Ransomware.RansomwareSignalKind.CanaryTouched,
            @"C:\Users\me\Documents\~decoy.docx",
            attribute: null,
            detectedAtUtc: null,
            health: refused);

        Assert.EndsWith(expected, ransomware, StringComparison.Ordinal);
    }
}
