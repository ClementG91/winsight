using WinSight.Core;
using WinSight.Persistence;
using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// Identity must change when the payload changes, and only then.
/// </summary>
/// <remarks>
/// <b>What the old identity missed.</b> It was (surface, name, target) and deliberately excluded the
/// arguments as noise. For an interpreter the arguments <i>are</i> the payload, so rewriting
/// <c>rundll32.exe …\ok.dll,Entry</c> as <c>rundll32.exe …\evil.dll,Start</c> produced an identical
/// identity and Guardian raised nothing - on the technique the persistence scanner exists to catch,
/// with the real-time monitor running.
///
/// The reason the arguments were excluded still has to hold, and it does: they come from a stored
/// value, not from a live process, so an unchanged entry hashes identically every scan.
/// </remarks>
public sealed class PersistenceIdentityArgumentsTests
{
    private static AutostartEntry Entry(string command) => new(
        AutostartVector.RunKey,
        "Updater",
        @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        command,
        ImagePath: @"C:\Windows\System32\rundll32.exe",
        ExpectedImagePath: @"C:\Windows\System32\rundll32.exe",
        ImageResolutionStatus.Present,
        new SignatureVerdict(SignatureState.SignedTrusted, "CN=Microsoft Windows"));

    [Fact]
    public void RewritingTheArgumentsChangesTheIdentity()
    {
        var before = PersistenceIdentity.FromEntry(
            Entry(@"rundll32.exe C:\Program Files\Vendor\ok.dll,Entry"));
        var after = PersistenceIdentity.FromEntry(
            Entry(@"rundll32.exe C:\Users\me\AppData\Roaming\evil.dll,Start"));

        Assert.NotEqual(before, after);
    }

    [Fact]
    public void TheSameEntryReadTwiceHashesIdentically()
    {
        const string Command = @"rundll32.exe C:\Program Files\Vendor\ok.dll,Entry";

        Assert.Equal(
            PersistenceIdentity.FromEntry(Entry(Command)),
            PersistenceIdentity.FromEntry(Entry(Command)));
    }

    /// <summary>
    /// Only the tail is taken. Including the whole command would make one value spelled with an
    /// environment variable and the same value spelled expanded look like two different entries -
    /// which is the instability the original design was right to avoid.
    /// </summary>
    [Theory]
    [InlineData(@"C:\Windows\explorer.exe /select,x", "/select,x")]
    [InlineData(@"""C:\Program Files\App\a.exe"" --flag", "--flag")]
    [InlineData(@"C:\Windows\explorer.exe", "")]
    [InlineData(@"""C:\Program Files\App\a.exe""", "")]
    [InlineData("", "")]
    [InlineData(null, "")]
    public void OnlyTheArgumentTailIsPartOfTheIdentity(string? command, string expected) =>
        Assert.Equal(expected, PersistenceIdentity.CanonicalizeArguments(command));

    /// <summary>Casing and spacing must not make one entry look like two.</summary>
    [Fact]
    public void CasingAndSpacingAreCanonicalised() =>
        Assert.Equal(
            PersistenceIdentity.CanonicalizeArguments(@"x.exe   C:\Users\Me\A.DLL,Start"),
            PersistenceIdentity.CanonicalizeArguments(@"x.exe c:\users\me\a.dll,start"));

    /// <summary>
    /// A forward slash in arguments is a switch introducer, not a path separator. Normalising it
    /// the way a path is normalised would corrupt the very string being compared.
    /// </summary>
    [Fact]
    public void SwitchIntroducersAreLeftAlone() =>
        Assert.Equal("/select,x", PersistenceIdentity.CanonicalizeArguments(@"explorer.exe /select,x"));

    /// <summary>
    /// A baseline written by the previous version has a different identity shape, and comparing
    /// against it would report every entry on the machine as new. The header is versioned so such a
    /// file reads as a first run instead.
    /// </summary>
    [Fact]
    public void ABaselineFromThePreviousShapeIsTreatedAsAFirstRun()
    {
        var path = Path.Combine(Path.GetTempPath(), $"winsight-baseline-{Guid.NewGuid():N}.tsv");
        File.WriteAllLines(path,
        [
            "#winsight-guardian-baseline v1",
            "RunKey\tUpdater\tc:\\windows\\system32\\rundll32.exe",
        ]);
        try
        {
            Assert.Null(new FilePersistenceBaselineStore(path).Load());
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ABaselineRoundTripsThroughTheStore()
    {
        var path = Path.Combine(Path.GetTempPath(), $"winsight-baseline-{Guid.NewGuid():N}.tsv");
        var store = new FilePersistenceBaselineStore(path);
        var identity = PersistenceIdentity.FromEntry(
            Entry(@"rundll32.exe C:\Program Files\Vendor\ok.dll,Entry"));
        try
        {
            store.Save([identity]);

            var loaded = store.Load();

            Assert.NotNull(loaded);
            Assert.Contains(identity, loaded!);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
