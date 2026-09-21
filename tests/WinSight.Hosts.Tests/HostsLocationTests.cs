using Xunit;

namespace WinSight.Hosts.Tests;

/// <summary>
/// Which hosts file Windows uses. The resolver reads it from the directory named by
/// <c>Tcpip\Parameters\DataBasePath</c>; a scan that always read the standard file reported a clean
/// copy while every override lived in the relocated one.
/// </summary>
public sealed class HostsLocationTests
{
    private const string Windows = @"C:\Windows";
    private const string System32 = @"C:\Windows\System32";
    private const string Standard = @"C:\Windows\System32\drivers\etc\hosts";

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(@"%SystemRoot%\System32\drivers\etc")]
    [InlineData(@"%windir%\system32\DRIVERS\etc\")]
    [InlineData(@"C:\Windows\System32\drivers\etc")]
    public void TheStandardDirectoryIsNotARelocation(string? registered)
    {
        var location = HostsReader.ResolveLocation(registered, Windows, System32);

        Assert.False(location.Relocated);
        Assert.Equal(Standard, location.Path);
    }

    [Theory]
    [InlineData(@"C:\ProgramData\netdb", @"C:\ProgramData\netdb\hosts")]
    [InlineData(@"%SystemRoot%\Temp\db", @"C:\Windows\Temp\db\hosts")]
    [InlineData(@"""D:\db\""", @"D:\db\hosts")]
    public void ARelocatedDirectoryIsReadAndSaidToBeRelocated(string registered, string expected)
    {
        var location = HostsReader.ResolveLocation(registered, Windows, System32);

        Assert.True(location.Relocated);
        Assert.Equal(expected, location.Path);
        Assert.Equal(registered, location.Registered);
    }

    /// <summary>
    /// A share stays a path - the reader refuses it before any network access, so it reads as
    /// unreadable - while a relative path or a variable with no trustworthy value has no answer.
    /// </summary>
    [Theory]
    [InlineData(@"\\server\share\etc", @"\\server\share\etc\hosts")]
    [InlineData(@"etc", null)]
    [InlineData(@"%TEMP%\db", null)]
    [InlineData(@"C:relative", null)]
    public void ALocationWithoutALocalAnswerIsStillAReportedRelocation(string registered, string? expected)
    {
        var location = HostsReader.ResolveLocation(registered, Windows, System32);

        Assert.True(location.Relocated);
        Assert.Equal(expected, location.Path);
    }

    /// <summary>
    /// The scanning process's own %SystemRoot% is not trusted (see <c>HostsPathTrustTests</c>): the
    /// value is expanded from the Windows directory passed in, never from the environment.
    /// </summary>
    [Fact]
    public void SystemRootIsExpandedFromTheWindowsDirectoryNotTheEnvironment()
    {
        var location = HostsReader.ResolveLocation(@"%SystemRoot%\System32\drivers\etc", @"E:\Win", @"E:\Win\System32");

        Assert.False(location.Relocated);
        Assert.Equal(@"E:\Win\System32\drivers\etc\hosts", location.Path);
    }

    /// <summary>On this machine the value is either absent or standard; it must resolve to a path.</summary>
    [Fact]
    public void TheRealLocationResolves()
    {
        var location = HostsReader.ResolveLocation();

        Assert.False(location.Unverified);
        Assert.NotNull(location.Path);
    }
}
