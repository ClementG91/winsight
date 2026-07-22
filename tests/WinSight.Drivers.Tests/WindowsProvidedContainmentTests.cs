using WinSight.Core;
using WinSight.Drivers;

using Xunit;

namespace WinSight.Drivers.Tests;

/// <summary>
/// Where a driver has to live before WinSight will call it one Windows ships.
/// </summary>
/// <remarks>
/// <b>Why the location matters as much as the signature.</b> A genuinely Microsoft-signed driver
/// running from a user-writable folder is the bring-your-own-vulnerable-driver case: real signature,
/// real Microsoft, loaded on purpose for what it lets an attacker do. Classing it as
/// <c>WindowsProvided</c> takes it out of the operator's view entirely, so the containment test is
/// the second half of the check and not a formality.
///
/// <b>Why these tests exist despite the scanner normalising first.</b> <c>KernelDriverScanner</c>
/// calls <c>Path.GetFullPath</c> before it ever reaches here, so a traversal is resolved in
/// production today. That makes the containment safe by a caller's habit rather than by its own
/// construction — and <see cref="KernelDriverTriage.IsWindowsProvided"/> is public. A rule this
/// consequential should hold for whoever calls it, not only for the one caller that happens to
/// prepare its input correctly.
/// </remarks>
public sealed class WindowsProvidedContainmentTests
{
    private const string System32 = @"C:\Windows\System32";
    private static readonly SignatureVerdict WindowsSigned =
        new(SignatureState.SignedTrusted, "CN=Microsoft Windows, O=Microsoft Corporation, C=US");

    private static bool Provided(string path) =>
        KernelDriverTriage.IsWindowsProvided(path, WindowsSigned, System32);

    [Theory]
    [InlineData(@"C:\Windows\System32\drivers\ntfs.sys")]
    [InlineData(@"c:\windows\system32\drivers\ntfs.sys")]
    public void ADriverGenuinelyInsideSystem32IsWindowsProvided(string path)
        => Assert.True(Provided(path));

    /// <summary>
    /// A path that walks back out of System32 is not inside it.
    /// </summary>
    /// <remarks>
    /// This is the failure that matters, because it fails <i>open</i>: a raw prefix comparison
    /// answers "inside System32" for a file that is demonstrably in a user-writable folder, and the
    /// driver disappears from the operator's view as something Windows ships.
    /// </remarks>
    [Theory]
    [InlineData(@"C:\Windows\System32\..\..\Users\Public\evil.sys")]
    [InlineData(@"C:\Windows\System32\..\Temp\evil.sys")]
    [InlineData(@"C:\Windows\System32\drivers\..\..\..\Users\Public\evil.sys")]
    public void APathThatWalksBackOutOfSystem32IsNotInsideIt(string path)
        => Assert.False(Provided(path));

    /// <summary>A directory that merely starts with the same text is a different directory.</summary>
    [Theory]
    [InlineData(@"C:\Windows\System32Extra\drivers\x.sys")]
    [InlineData(@"C:\Windows\System32.old\x.sys")]
    [InlineData(@"C:\Windows\System32evil.sys")]
    public void ADirectoryThatMerelyStartsLikeSystem32IsNotInsideIt(string path)
        => Assert.False(Provided(path));

    /// <summary>
    /// A legitimate driver spelled with the other separator is still inside System32.
    /// </summary>
    /// <remarks>
    /// The opposite failure direction, and the quieter one: reporting an in-box driver as
    /// third-party adds a row to a list several hundred long, where it is never looked at again.
    /// Both halves of the comparison are normalised so neither spelling decides the answer.
    /// </remarks>
    [Theory]
    [InlineData(@"C:/Windows/System32/drivers/ntfs.sys")]
    [InlineData(@"C:\Windows\.\System32\drivers\ntfs.sys")]
    [InlineData(@"C:\Windows\System32\.\drivers\ntfs.sys")]
    public void AnAlternativeSpellingOfTheSamePlaceIsStillInside(string path)
        => Assert.True(Provided(path));

    [Fact]
    public void ATrailingSeparatorOnTheRootDoesNotChangeTheAnswer()
    {
        var withSlash = KernelDriverTriage.IsWindowsProvided(
            @"C:\Windows\System32\drivers\ntfs.sys", WindowsSigned, @"C:\Windows\System32\");

        Assert.True(withSlash);
    }

    /// <summary>
    /// The system directory itself is not "inside" itself, and neither is a sibling of it.
    /// </summary>
    [Theory]
    [InlineData(@"C:\Windows\System32")]
    [InlineData(@"C:\Windows")]
    [InlineData(@"C:\")]
    public void AnAncestorOrTheRootItselfIsNotInside(string path)
        => Assert.False(Provided(path));

    /// <summary>
    /// An unusable path answers "not Windows-provided" rather than throwing or vouching.
    /// </summary>
    /// <remarks>
    /// Failing closed is the right direction here: a driver whose location WinSight cannot establish
    /// is one it must not present as shipped by Windows. It then falls through to the signature-based
    /// verdict, where it is reported as context rather than hidden.
    ///
    /// A relative path is the interesting member of this set: it resolves against the current
    /// directory, which is never System32 for a scanner, so it must not slip through as contained.
    ///
    /// Paths carrying characters NTFS forbids are deliberately <i>not</i> asserted here. They still
    /// resolve lexically inside System32, and that is the correct answer to the question this method
    /// asks — containment is lexical. No such file can exist, so no such file can carry the trusted
    /// Microsoft signature the first half of <see cref="KernelDriverTriage.IsWindowsProvided"/>
    /// requires; asserting on the combination would be testing an input that cannot occur.
    /// </remarks>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    [InlineData("relative\\path\\x.sys")]
    [InlineData("..\\..\\Users\\Public\\evil.sys")]
    public void AnUnusablePathIsNeverVouchedFor(string? path)
        => Assert.False(KernelDriverTriage.IsWindowsProvided(path, WindowsSigned, System32));

    /// <summary>
    /// Containment never overrules the signature, in either direction.
    /// </summary>
    [Theory]
    [InlineData(SignatureState.Unsigned)]
    [InlineData(SignatureState.SignedUntrusted)]
    [InlineData(SignatureState.Unknown)]
    [InlineData(SignatureState.Missing)]
    public void BeingInsideSystem32DoesNotMakeADriverWindowsProvided(SignatureState state)
        => Assert.False(KernelDriverTriage.IsWindowsProvided(
            @"C:\Windows\System32\drivers\x.sys", new SignatureVerdict(state, "CN=Microsoft Windows"), System32));

    /// <summary>
    /// The bring-your-own-vulnerable-driver shape, stated as a single test.
    /// </summary>
    [Fact]
    public void AGenuinelyMicrosoftSignedDriverRunningFromADownloadFolderIsNotHidden()
    {
        var byovd = KernelDriverTriage.IsWindowsProvided(
            @"C:\Users\me\Downloads\rtcore64.sys", WindowsSigned, System32);

        Assert.False(byovd);
        Assert.Equal(
            KernelDriverConcern.ThirdParty,
            KernelDriverTriage.Concern(new KernelDriver(
                "rtcore64", DriverKind.Kernel, DriverStart.Manual,
                @"C:\Users\me\Downloads\rtcore64.sys", @"C:\Users\me\Downloads\rtcore64.sys",
                WindowsSigned, IsWindowsProvided: byovd)));
    }
}
