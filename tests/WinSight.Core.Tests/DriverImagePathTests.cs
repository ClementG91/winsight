using Xunit;

namespace WinSight.Core.Tests;

/// <summary>
/// Which file a driver registration makes Windows load, as the driver and input-filter scans see it.
/// </summary>
/// <remarks>
/// <b>The regression these pin.</b> Both scans fell back to <c>System32\drivers\{service}.sys</c>
/// whenever the registered image could not be mapped or found, although Windows uses that default
/// only when <c>ImagePath</c> is absent. A driver registered as
/// <c>\Device\HarddiskVolume3\x\kbdclass.sys</c>, or at a path whose file the scan could not see, was
/// verified as the in-box <c>kbdclass.sys</c> and reported as shipped by Windows.
/// </remarks>
public sealed class DriverImagePathTests
{
    private const string Windows = @"C:\Windows";

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void OnlyAnAbsentImagePathFallsBackToTheDriversFolder(string? registered)
    {
        var location = DriverImagePath.Locate("kbdclass", registered, Windows);

        Assert.Equal(DriverImageSource.Default, location.Source);
        Assert.Equal(@"C:\Windows\System32\drivers\kbdclass.sys", location.Path);
        Assert.Null(location.Registered);
    }

    [Fact]
    public void ARegisteredImageIsKeptEvenWhenAnInBoxFileHasItsName()
    {
        var location = DriverImagePath.Locate("kbdclass", @"\??\C:\ProgramData\x\kbdclass.sys", Windows);

        Assert.Equal(DriverImageSource.Registered, location.Source);
        Assert.Equal(@"C:\ProgramData\x\kbdclass.sys", location.Path);
    }

    /// <summary>
    /// Object-manager names and shares reach no local Win32 path. Each used to become either a path
    /// under the current drive or working directory, or the in-box file of the same name.
    /// </summary>
    [Theory]
    [InlineData(@"\Device\HarddiskVolume3\x\kbdclass.sys")]
    [InlineData(@"\??\GLOBALROOT\Device\HarddiskVolume3\x\kbdclass.sys")]
    [InlineData(@"\??\Volume{00000000-0000-0000-0000-000000000000}\x\kbdclass.sys")]
    [InlineData(@"\??\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\drivers\kbdclass.sys")]
    [InlineData(@"\ArcName\multi(0)disk(0)rdisk(0)partition(3)\kbdclass.sys")]
    [InlineData(@"\\server\share\kbdclass.sys")]
    [InlineData(@"\??\UNC\server\share\kbdclass.sys")]
    [InlineData(@"C:kbdclass.sys")]
    public void ARegisteredImageNoLocalPathReachesIsUnresolvableNotTheDefault(string registered)
    {
        var location = DriverImagePath.Locate("kbdclass", registered, Windows);

        Assert.Equal(DriverImageSource.Unresolvable, location.Source);
        Assert.Null(location.Path);
        Assert.Equal(registered, location.Registered);
    }

    [Theory]
    [InlineData(@"\SystemRoot\System32\drivers\x.sys")]
    [InlineData(@"SystemRoot\System32\drivers\x.sys")]
    [InlineData(@"System32\drivers\x.sys")]
    public void SystemRootAndRelativeFormsResolveUnderTheWindowsDirectory(string registered) =>
        Assert.Equal(@"C:\Windows\System32\drivers\x.sys", DriverImagePath.Normalize(registered, Windows));

    [Theory]
    [InlineData(@"\??\D:\drivers\x.sys")]
    [InlineData(@"\DosDevices\D:\drivers\x.sys")]
    [InlineData(@"\GLOBAL??\D:\drivers\x.sys")]
    [InlineData(@"D:\drivers\x.sys")]
    [InlineData("  \"D:\\drivers\\x.sys\"  ")]
    public void EverySpellingOfADrivePathResolvesToIt(string registered) =>
        Assert.Equal(@"D:\drivers\x.sys", DriverImagePath.Normalize(registered, Windows));

    /// <summary>
    /// A key name may contain '/', which a path treats as a separator. The default location is built
    /// from the name, so such a name must not steer it out of the drivers folder.
    /// </summary>
    [Theory]
    [InlineData("a/../../../evil")]
    [InlineData("..")]
    [InlineData(".")]
    [InlineData("x:y")]
    public void AServiceNameThatIsNotAFileNameHasNoDefaultImage(string serviceName)
    {
        var location = DriverImagePath.Locate(serviceName, null, Windows);

        Assert.Equal(DriverImageSource.Unresolvable, location.Source);
        Assert.Null(location.Path);
    }
}
