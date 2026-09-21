using Xunit;

namespace WinSight.Response.Tests;

public sealed class ProtectedProcessesIdentityTests
{
    private static ProcessIdentity Identity(int pid, string path) => new(pid, 1, path, null);

    [Fact]
    public void WindowsCriticalNamesRequireTheRealSystemDirectory()
    {
        const string windows = @"C:\Windows";
        var product = new[] { @"C:\Program Files\WinSight" };

        Assert.True(ProtectedProcesses.IsProtected(
            Identity(100, @"C:\Windows\System32\lsass.exe"), windows, product, currentProcessId: 999));
        Assert.True(ProtectedProcesses.IsProtected(
            Identity(100, @"C:\Windows\SysWOW64\svchost.exe"), windows, product, currentProcessId: 999));
        Assert.False(ProtectedProcesses.IsProtected(
            Identity(100, @"C:\Temp\lsass.exe"), windows, product, currentProcessId: 999));
        Assert.False(ProtectedProcesses.IsProtected(
            Identity(100, @"C:\Windows\Temp\svchost.exe"), windows, product, currentProcessId: 999));
    }

    [Fact]
    public void WinSightNamesRequireCurrentIdentityOrTheProductDirectory()
    {
        const string windows = @"C:\Windows";
        var product = new[] { @"C:\Program Files\WinSight" };

        Assert.True(ProtectedProcesses.IsProtected(
            Identity(100, @"C:\Program Files\WinSight\winsight-dashboard.exe"),
            windows, product, currentProcessId: 999));
        Assert.True(ProtectedProcesses.IsProtected(
            Identity(999, @"C:\Temp\renamed.exe"), windows, product, currentProcessId: 999));
        Assert.False(ProtectedProcesses.IsProtected(
            Identity(100, @"C:\Temp\winsight-dashboard.exe"), windows, product, currentProcessId: 999));
    }

    [Fact]
    public void AnIdentityWithoutAVerifiableAbsolutePathFailsClosed()
    {
        Assert.True(ProtectedProcesses.IsProtected(
            Identity(100, string.Empty), @"C:\Windows", [@"C:\Program Files\WinSight"], 999));
        Assert.True(ProtectedProcesses.IsProtected(
            Identity(100, "relative.exe"), @"C:\Windows", [@"C:\Program Files\WinSight"], 999));
    }
}
