using WinSight.Hijack;

using Xunit;

namespace WinSight.Hijack.Tests;

/// <summary>
/// The command-line shapes an adversarial pass found this rule reading wrongly, or not at all.
/// </summary>
/// <remarks>
/// Each case here is a place the scan was either silent about a real hijack point, or would have
/// named a path that cannot exist. Both are failures of the same promise: the candidate list is the
/// finding, so it has to be exactly the set Windows would try — no more, no less.
/// </remarks>
public sealed class UnquotedPathEdgeCaseTests
{
    // ---- UNC: prefix-searched like any other path, and was reported as nothing --------------

    [Fact]
    public void AUncServicePathIsPrefixSearchedJustLikeADrivePath()
    {
        var candidates = UnquotedPath.HijackCandidates(@"\\server\share\My App\svc.exe -k");

        Assert.Equal([@"\\server\share\My.exe"], candidates);
    }

    [Fact]
    public void AUncCandidateNeverNamesTheServerOrTheShare()
    {
        // \\server.exe and \\server\share.exe are not files anyone can plant.
        var candidates = UnquotedPath.HijackCandidates(@"\\server\share top\level\svc.exe");

        Assert.DoesNotContain(candidates, c => c.Equals(@"\\server.exe", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(candidates, c => c.Equals(@"\\server\share.exe", StringComparison.OrdinalIgnoreCase));
    }

    // ---- Namespaces this rule genuinely does not model --------------------------------------

    [Theory]
    // Kernel-loaded driver paths: CreateProcess is never involved.
    [InlineData(@"\SystemRoot\System32\drivers\foo.sys")]
    [InlineData(@"\??\C:\Windows\System32\drivers\foo.sys")]
    // Extended-length and device namespaces bypass the parsing modelled here.
    [InlineData(@"\\?\C:\Program Files\App\svc.exe")]
    [InlineData(@"\\.\GLOBALROOT\Device\Foo\svc.exe")]
    public void PathsOutsideTheModelReportNothing(string commandLine)
        => Assert.Empty(UnquotedPath.HijackCandidates(commandLine));

    // ---- A root is not a plantable file ------------------------------------------------------

    [Fact]
    public void ADriveRootIsNeverOfferedAsACandidate()
    {
        var candidates = UnquotedPath.HijackCandidates(@"C:\Program Files\App\svc.exe");

        Assert.Equal([@"C:\Program.exe"], candidates);
        Assert.DoesNotContain(@"C:.exe", candidates);
    }

    // ---- Repeated separators must not manufacture an impossible path -------------------------

    [Fact]
    public void ConsecutiveSpacesDoNotProduceACandidateWithATrailingSpace()
    {
        // Windows drops trailing spaces from a path component, so both readings are C:\Program.exe.
        var candidates = UnquotedPath.HijackCandidates(@"C:\Program  Files\App\svc.exe");

        Assert.Equal([@"C:\Program.exe"], candidates);
    }

    // ---- Registered images that are not .exe -------------------------------------------------

    [Theory]
    [InlineData(@"C:\Program Files\App\run.bat")]
    [InlineData(@"C:\Program Files\App\run.cmd")]
    [InlineData(@"C:\Program Files\App\run.scr")]
    [InlineData(@"C:\Program Files\App\run.pif")]
    public void ANonExeImageIsStillPrefixSearched(string commandLine)
    {
        // The candidate is always .exe: that is what CreateProcess appends to a guessed prefix.
        Assert.Equal([@"C:\Program.exe"], UnquotedPath.HijackCandidates(commandLine));
    }

    // ---- Widening the extensions must not re-open the argument bug ---------------------------

    /// <summary>
    /// A domain name in an argument must never be read as the registered image.
    /// </summary>
    /// <remarks>
    /// This is why <c>.com</c> is not in the extension set. Reading the <c>.com</c> here would make
    /// the span the whole command line, and the first candidate would be <c>C:\Program.exe</c>
    /// followed by readings of the arguments — but worse, on a command line whose image token has no
    /// extension it would name the real executable as a plantable candidate. Saying nothing is the
    /// honest answer when no token in the line names an image this rule recognises.
    /// </remarks>
    [Fact]
    public void ADomainNameInAnArgumentIsNotReadAsTheExecutable()
        => Assert.Empty(UnquotedPath.HijackCandidates(@"C:\Program Files\App\run --host example.com"));

    /// <summary>
    /// An executable whose <i>file name</i> contains a space still resolves.
    /// </summary>
    /// <remarks>
    /// Pinned because an earlier attempt at the argument guard required the extension's token to
    /// contain a directory separator. That rule looked right and silently broke this: in
    /// <c>...\sub dir\program name.exe</c> the last token is <c>name.exe</c>, which has no separator,
    /// so the whole command line reported nothing — a real hijack point going quiet, which is the
    /// worse of the two errors. Kept as an explicit case so the guard cannot be reintroduced.
    /// </remarks>
    [Fact]
    public void AnExecutableWithASpaceInItsFileNameIsStillRead()
    {
        var candidates = UnquotedPath.HijackCandidates(@"c:\program files\sub dir\program name.exe");

        Assert.Equal(
            [@"c:\program.exe", @"c:\program files\sub.exe", @"c:\program files\sub dir\program.exe"],
            candidates);
    }

    [Fact]
    public void ABareImageNameInAnArgumentIsNotReadAsTheExecutable()
    {
        // Nothing here names an absolute image, so there is no prefix Windows would try.
        Assert.Empty(UnquotedPath.HijackCandidates(@"runner --tool foo.exe"));
    }

    [Fact]
    public void TheEarliestQualifyingExtensionWinsAcrossAllOfThem()
    {
        // .exe appears after .bat here; the executable is still the first token that names a path.
        var candidates = UnquotedPath.HijackCandidates(@"C:\Program Files\App\run.bat C:\other\x.exe");

        Assert.Equal([@"C:\Program.exe"], candidates);
    }

    // ---- The properties that must hold for every input ---------------------------------------

    [Theory]
    [InlineData(@"C:\Program Files\App\svc.exe -k netsvcs")]
    [InlineData(@"\\server\share\My App\svc.exe")]
    [InlineData(@"C:\Program  Files\App\svc.exe")]
    [InlineData(@"C:\Program Files\Common Files\App\svc.exe")]
    public void EveryCandidateIsAnAbsolutePathBelowItsOwnRootAndUnique(string commandLine)
    {
        var candidates = UnquotedPath.HijackCandidates(commandLine);

        Assert.NotEmpty(candidates);
        Assert.Equal(candidates.Distinct(StringComparer.OrdinalIgnoreCase).Count(), candidates.Count);
        Assert.All(candidates, candidate =>
        {
            Assert.True(Path.IsPathFullyQualified(candidate), $"{candidate} is not absolute.");
            Assert.NotEqual(Path.GetPathRoot(candidate), candidate);
            Assert.EndsWith(".exe", candidate, StringComparison.Ordinal);
            // A trailing space before the extension would name a file Windows cannot create.
            Assert.False(candidate.Contains(" .exe", StringComparison.Ordinal), candidate);
        });
    }
}
