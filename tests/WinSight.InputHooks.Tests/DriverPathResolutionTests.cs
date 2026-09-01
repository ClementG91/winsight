using WinSight.InputHooks;
using Xunit;

namespace WinSight.InputHooks.Tests;

/// <summary>
/// Turning a service's registered <c>ImagePath</c> into a file on disk.
/// </summary>
/// <remarks>
/// <b>Why this was worth writing.</b> A keyboard filter is named by its service, and the image that
/// service points at is what gets an Authenticode verdict. Every prefix form Windows uses here -
/// <c>\SystemRoot\</c>, the bare <c>SystemRoot\</c>, the <c>\??\</c> device prefix, and a bare
/// relative name - was unreachable from a test, because reaching it through the public scan means
/// writing to <c>HKLM\SYSTEM\CurrentControlSet\Services</c> on the machine running the suite. So the
/// one piece of parsing in this assembly had no tests at all, on the path that decides which file
/// gets verified. Resolve the wrong file and the filter is reported against somebody else's
/// signature.
/// </remarks>
public sealed class DriverPathResolutionTests
{
    private static readonly string Windows =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AnAbsentImagePathResolvesToNothing(string? registered) =>
        Assert.Null(InputFilterScanner.NormalizeDriverPath(registered));

    [Fact]
    public void TheSystemRootPrefixIsExpanded() =>
        Assert.Equal(
            Path.Combine(Windows, @"System32\drivers\kbdclass.sys"),
            InputFilterScanner.NormalizeDriverPath(@"\SystemRoot\System32\drivers\kbdclass.sys"));

    /// <summary>Windows writes it both ways; the leading separator is not guaranteed.</summary>
    [Fact]
    public void TheBareSystemRootPrefixIsExpanded() =>
        Assert.Equal(
            Path.Combine(Windows, @"System32\drivers\kbdclass.sys"),
            InputFilterScanner.NormalizeDriverPath(@"SystemRoot\System32\drivers\kbdclass.sys"));

    /// <summary>
    /// The NT object-manager prefix names an absolute path already; stripping it must not send the
    /// result through the Windows-relative branch below.
    /// </summary>
    [Fact]
    public void TheDevicePrefixIsStrippedRatherThanExpanded() =>
        Assert.Equal(
            @"C:\Program Files\Vendor\filter.sys",
            InputFilterScanner.NormalizeDriverPath(@"\??\C:\Program Files\Vendor\filter.sys"));

    [Theory]
    [InlineData(@"\\server\share\filter.sys")]
    [InlineData(@"\??\UNC\server\share\filter.sys")]
    public void ARemotePathIsRefusedBeforeTheFilesystemIsTouched(string path) =>
        Assert.Null(InputFilterScanner.NormalizeDriverPath(path));

    [Theory]
    [InlineData(@"\??\Volume{00000000-0000-0000-0000-000000000000}\filter.sys")]
    [InlineData(@"\??\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\filter.sys")]
    public void AnUnsupportedDevicePathIsNotMistakenForAWorkingDirectoryPath(string path) =>
        Assert.Null(InputFilterScanner.NormalizeDriverPath(path));

    [Fact]
    public void AnAlreadyRootedPathIsLeftAlone() =>
        Assert.Equal(
            @"D:\drivers\filter.sys",
            InputFilterScanner.NormalizeDriverPath(@"D:\drivers\filter.sys"));

    /// <summary>
    /// A relative value is relative to the Windows directory, which is where the service control
    /// manager resolves it from - not to the scanner's working directory.
    /// </summary>
    [Fact]
    public void ARelativePathIsResolvedAgainstTheWindowsDirectory() =>
        Assert.Equal(
            Path.Combine(Windows, @"System32\drivers\filter.sys"),
            InputFilterScanner.NormalizeDriverPath(@"System32\drivers\filter.sys"));

    [Fact]
    public void SurroundingQuotesAndWhitespaceAreRemoved() =>
        Assert.Equal(
            @"C:\drivers\filter.sys",
            InputFilterScanner.NormalizeDriverPath("  \"C:\\drivers\\filter.sys\"  "));

    [Fact]
    public void AnEnvironmentVariableIsExpanded()
    {
        var expanded = InputFilterScanner.NormalizeDriverPath(@"%SystemRoot%\System32\drivers\x.sys");

        Assert.Equal(Path.Combine(Windows, @"System32\drivers\x.sys"), expanded);
    }

    /// <summary>
    /// A value that is nothing but quotes is absent, not a rooted path of length zero - the
    /// difference between resolving to null and combining the Windows directory with an empty
    /// string, which names the Windows directory itself.
    /// </summary>
    [Theory]
    [InlineData("\"\"")]
    [InlineData("  \"  \"  ")]
    public void AValueThatIsOnlyQuotesResolvesToNothing(string registered) =>
        Assert.Null(InputFilterScanner.NormalizeDriverPath(registered));

    /// <summary>
    /// A filter name is a service name, never a path. One containing a separator - or naming the
    /// current or parent directory - is refused rather than combined into
    /// <c>System32\drivers\{name}.sys</c>, where <c>..\..\evil</c> would escape the drivers folder
    /// entirely and get somebody else's file verified in a keyboard filter's name.
    /// </summary>
    [Theory]
    [InlineData(@"..\..\Temp\evil")]
    [InlineData("sub/dir")]
    [InlineData(".")]
    [InlineData("..")]
    public void AFilterNameThatIsReallyAPathIsRefused(string name)
    {
        var (path, unreadable) = InputFilterScanner.ResolveDriverPath(name);

        Assert.Null(path);
        Assert.True(unreadable);
    }

    /// <summary>
    /// A name that resolves to no file on disk is reported as resolved-to-nothing rather than as
    /// unreadable: nothing failed, the file simply is not there.
    /// </summary>
    [Fact]
    public void AnUnknownServiceResolvesToNothingWithoutClaimingAFailure()
    {
        var (path, unreadable) = InputFilterScanner.ResolveDriverPath(
            "winsight-no-such-filter-driver");

        Assert.Null(path);
        Assert.False(unreadable);
    }

    /// <summary>
    /// The class driver Windows itself installs is present on every supported machine, so this is
    /// the one end-to-end assertion the resolution path can make without writing to the registry.
    /// </summary>
    [Fact]
    public void TheWindowsKeyboardClassDriverResolvesToItsFile()
    {
        var (path, unreadable) = InputFilterScanner.ResolveDriverPath("kbdclass");

        Assert.False(unreadable);
        Assert.NotNull(path);
        Assert.True(File.Exists(path));
        Assert.EndsWith("kbdclass.sys", path, StringComparison.OrdinalIgnoreCase);
    }
}
