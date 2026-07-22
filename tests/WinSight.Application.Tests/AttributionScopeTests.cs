using WinSight.Application;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// Which file writes attribution is allowed to remember.
/// </summary>
/// <remarks>
/// This filter is the difference between a ransomware alert that says "decoy.docx was touched" and
/// one that says which program touched it. It is also the thing standing between a small,
/// time-bounded correlation index and the thousands of writes a second an ordinary desktop performs,
/// so it has to be exactly as narrow as it is — no narrower, or the feature reports nothing.
/// </remarks>
public sealed class AttributionScopeTests
{
    private const string StartupFolder =
        @"C:\Users\me\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup";

    private static AttributionScope Scope() => new([StartupFolder]);

    // ---- The volume-root problem this filter exists to survive --------------------------------

    /// <summary>
    /// The filter runs on the path as the kernel spells it, before normalisation.
    /// </summary>
    /// <remarks>
    /// A trace session can deliver <c>\Device\HarddiskVolume3\Users\…</c> where the operator's folder
    /// is <c>C:\Users\…</c>. A filter comparing full paths matches neither reliably, and the failure
    /// is total and silent: every startup-folder write is dropped and attribution simply reports
    /// nothing, which is indistinguishable from a quiet machine. Matching the root-relative tail is
    /// correct under either spelling, which is the point — the code should not be betting on which
    /// one arrives.
    /// </remarks>
    [Theory]
    [InlineData(@"C:\Users\me\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.lnk")]
    [InlineData(@"\Device\HarddiskVolume3\Users\me\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.lnk")]
    [InlineData(@"\??\C:\Users\me\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.lnk")]
    [InlineData(@"D:\Users\me\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.lnk")]
    public void AStartupFolderWriteIsRecordedHoweverTheKernelSpellsThePath(string path)
        => Assert.True(Scope().ShouldRecord(path));

    [Theory]
    [InlineData(@"C:\Users\me\Documents\report.docx")]
    [InlineData(@"\Device\HarddiskVolume3\Windows\Temp\whatever.tmp")]
    [InlineData(@"C:\Program Files\App\app.exe")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void OrdinaryWritesAreNotRecorded(string? path)
        => Assert.False(Scope().ShouldRecord(path));

    // ---- Decoys ------------------------------------------------------------------------------

    [Fact]
    public void ADecoyIsRecordedOnlyOnceItHasBeenPlanted()
    {
        var scope = Scope();
        const string canary = @"C:\Users\me\Documents\~winsight-decoy.docx";

        // Before protection is switched on the decoy does not exist and must not be watched.
        Assert.False(scope.ShouldRecord(canary));

        scope.WatchCanaries([canary]);

        Assert.True(scope.ShouldRecord(canary));
        Assert.True(scope.ShouldRecord(@"\Device\HarddiskVolume3\Users\me\Documents\~winsight-decoy.docx"));
    }

    /// <summary>
    /// A decoy is matched exactly, never by its folder.
    /// </summary>
    /// <remarks>
    /// Admitting the whole directory is the mistake that would quietly destroy this feature:
    /// Documents, Desktop and Pictures are among the busiest paths on a desktop, and the correlation
    /// index would evict every useful observation within seconds — full and useless at the exact
    /// moment a detection asked it a question.
    /// </remarks>
    [Fact]
    public void TheDecoysFolderIsNotWatchedWholesale()
    {
        var scope = Scope();
        scope.WatchCanaries([@"C:\Users\me\Documents\~winsight-decoy.docx"]);

        Assert.False(scope.ShouldRecord(@"C:\Users\me\Documents\holiday.jpg"));
        Assert.False(scope.ShouldRecord(@"C:\Users\me\Documents\~winsight-decoy.docx.encrypted"));
    }

    [Fact]
    public void ForgettingTheDecoysStopsRecordingThem()
    {
        var scope = Scope();
        const string canary = @"C:\Users\me\Documents\~winsight-decoy.docx";
        scope.WatchCanaries([canary]);

        scope.ForgetCanaries();

        Assert.False(scope.ShouldRecord(canary));
        // Startup coverage is not affected by protection being switched off.
        Assert.True(scope.ShouldRecord(StartupFolder + @"\evil.lnk"));
    }

    [Fact]
    public void ReplantingSwapsTheWatchedSetRatherThanAccumulating()
    {
        var scope = Scope();
        scope.WatchCanaries([@"C:\Users\me\Documents\~old.docx"]);

        scope.WatchCanaries([@"C:\Users\me\Documents\~new.docx"]);

        Assert.False(scope.ShouldRecord(@"C:\Users\me\Documents\~old.docx"));
        Assert.True(scope.ShouldRecord(@"C:\Users\me\Documents\~new.docx"));
    }

    // ---- Root stripping ----------------------------------------------------------------------

    [Theory]
    [InlineData(@"C:\Users\me\x.txt", @"\Users\me\x.txt")]
    [InlineData(@"\Device\HarddiskVolume3\Users\me\x.txt", @"\Users\me\x.txt")]
    [InlineData(@"\??\C:\Users\me\x.txt", @"\Users\me\x.txt")]
    [InlineData(@"\\?\C:\Users\me\x.txt", @"\Users\me\x.txt")]
    [InlineData(@"C:/Users/me/x.txt", @"\Users\me\x.txt")]
    [InlineData(@"\Users\me\x.txt", @"\Users\me\x.txt")]
    [InlineData("C:", "")]
    [InlineData("", "")]
    [InlineData(null, "")]
    public void RootRelativeStripsWhicheverRootThePathWears(string? path, string expected)
        => Assert.Equal(expected, AttributionScope.RootRelative(path));

    [Fact]
    public void ADefaultScopeWatchesTheRealStartupFolders()
    {
        // Guards the wiring: a scope constructed with no arguments must cover something, or the
        // dashboard would run a trace session that records no file at all.
        Assert.NotEmpty(AttributionScope.DefaultStartupFolders());

        var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        Assert.True(new AttributionScope().ShouldRecord(Path.Combine(startup, "evil.lnk")));
    }
}
