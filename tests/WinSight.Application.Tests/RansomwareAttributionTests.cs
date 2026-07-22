using WinSight.Application;
using WinSight.Attribution;
using WinSight.Ransomware;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// The sentence an operator reads when their files are being encrypted.
/// </summary>
/// <remarks>
/// Ransomware is the one detection where minutes matter, and until now it named what was touched and
/// never who touched it. "CanaryTouched: decoy.docx" says something is wrong; naming the writing
/// process says what to terminate. These pin both the presence of the author and its absence, because
/// a missing author is a normal answer here — attribution may not be running at all — and must not
/// turn into a blank or a guess.
/// </remarks>
public sealed class RansomwareAttributionTests
{
    private static readonly DateTimeOffset At = new(2026, 7, 22, 12, 0, 0, TimeSpan.Zero);
    private const string Decoy = @"C:\Users\me\Documents\~winsight-decoy.docx";

    private static Func<string?, DateTimeOffset, WriteObservation?> Names(
        string executable, int pid, bool exact = true) =>
        (target, when) => new WriteObservation(when, pid, executable, target ?? string.Empty, exact);

    [Fact]
    public void ATouchedDecoyNamesTheProcessThatTouchedIt()
    {
        var detail = RansomwarePresenter.AlertDetail(
            RansomwareSignalKind.CanaryTouched, Decoy,
            Names(@"C:\Users\me\AppData\Local\Temp\x.exe", 8121), At);

        Assert.Contains(@"C:\Users\me\AppData\Local\Temp\x.exe", detail, StringComparison.Ordinal);
        Assert.Contains("pid 8121", detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// The journal keeps the full path; the balloon keeps only the file name.
    /// </summary>
    /// <remarks>
    /// A balloon can be read over someone's shoulder. The journal is opened deliberately, on one's
    /// own machine, by someone who has just been told their files are being encrypted — exactly the
    /// moment to be told the whole path rather than protected from it.
    /// </remarks>
    [Fact]
    public void TheJournalLineCarriesTheFullPathWhileTheBalloonDoesNot()
    {
        var journal = RansomwarePresenter.AlertDetail(RansomwareSignalKind.CanaryTouched, Decoy);
        var balloon = RansomwarePresenter.Detail(RansomwareSignalKind.CanaryTouched, Decoy);

        Assert.Contains(Decoy, journal, StringComparison.Ordinal);
        Assert.DoesNotContain(@"C:\Users\me", balloon, StringComparison.Ordinal);
        Assert.Contains("~winsight-decoy.docx", balloon, StringComparison.Ordinal);
    }

    [Fact]
    public void NoAttributionMeansNoAuthorRatherThanAnEmptyOne()
    {
        var detail = RansomwarePresenter.AlertDetail(RansomwareSignalKind.CanaryTouched, Decoy);

        Assert.DoesNotContain("written by", detail, StringComparison.Ordinal);
        Assert.Contains("CanaryTouched", detail, StringComparison.Ordinal);
    }

    [Fact]
    public void AWatchingAttributionThatCannotAnswerIsAlsoNoAuthor()
    {
        // Attribution running and having no matching observation is a normal outcome: the writer may
        // have acted before the session opened. It must read the same as not watching, never as a
        // half-filled sentence.
        var detail = RansomwarePresenter.AlertDetail(
            RansomwareSignalKind.CanaryTouched, Decoy, (_, _) => null, At);

        Assert.DoesNotContain("written by", detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// A bare-name launch is named, never presented as a located file.
    /// </summary>
    /// <remarks>
    /// Living-off-the-land ransomware runs as <c>powershell.exe</c> through the search path, so the
    /// kernel reports a name and no path. Saying so is far better than silence, but an operator
    /// deciding what to terminate must be able to tell a name from a path they can go and inspect.
    /// </remarks>
    [Fact]
    public void ABareNameAuthorIsMarkedAsHavingNoKnownPath()
    {
        var detail = RansomwarePresenter.AlertDetail(
            RansomwareSignalKind.CanaryTouched, Decoy,
            Names("powershell.exe", 4242, exact: false), At);

        Assert.Contains("powershell.exe", detail, StringComparison.Ordinal);
        Assert.Contains("full path unknown", detail, StringComparison.Ordinal);
    }

    [Fact]
    public void ABurstIsStillReportedWhenNothingCanNameIt()
    {
        // A rename/delete burst normally has no author by design: attributing it would mean
        // recording every write in the user's document folders. The alert must not be weakened by
        // that — it is still a detection, with or without a name.
        var detail = RansomwarePresenter.AlertDetail(
            RansomwareSignalKind.Rename, @"C:\Users\me\Documents\a.docx", (_, _) => null, At);

        Assert.Contains("Rename", detail, StringComparison.Ordinal);
    }

    [Fact]
    public void TheAttributionQueryUsesTheTouchedPathAndTheDetectionTime()
    {
        string? askedTarget = null;
        DateTimeOffset askedAt = default;

        _ = RansomwarePresenter.AlertDetail(
            RansomwareSignalKind.CanaryTouched, Decoy,
            (target, when) => { askedTarget = target; askedAt = when; return null; },
            At);

        Assert.Equal(Decoy, askedTarget);
        Assert.Equal(At, askedAt);
    }
}
