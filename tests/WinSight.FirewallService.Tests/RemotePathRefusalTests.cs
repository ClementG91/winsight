using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

/// <summary>
/// The path-trust inspection refuses anything that is not on this machine's own storage.
/// </summary>
/// <remarks>
/// <b>Why this is a security fix and not tidiness.</b> The inspection decides whether a SYSTEM
/// service may trust a path, and it decides by asking the filesystem who owns each component and
/// what its ACL grants. On a UNC path those answers come from the remote server. A server an
/// attacker controls reports whatever owner and ACL make the check pass, so the trust decision
/// stops being this machine's to make - and the check that exists to refuse an attacker-controlled
/// path would be reading the attacker's answers to decide.
///
/// Reaching the path at all is the second problem. The service runs as SYSTEM, so touching
/// <c>\\attacker\share\x.exe</c> authenticates to that host as the machine account. A check whose
/// only purpose is caution would be handing out an NTLM coercion primitive for free.
///
/// The refusal is syntactic and happens before a single component is opened, so nothing is read
/// from the remote host in the course of declining to trust it.
/// </remarks>
public sealed class RemotePathRefusalTests
{
    [Theory]
    [InlineData(@"\\server\share\WinSight\winsight-firewall-service.exe")]
    [InlineData(@"\\127.0.0.1\c$\Windows\System32\svchost.exe")]
    [InlineData(@"\\?\UNC\server\share\x.exe")]
    [InlineData(@"\\?\C:\ProgramData\WinSight\x.exe")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData("//server/share/x.exe")]
    public void ARemoteOrDeviceNamespacePathIsNotOnLocalStorage(string path) =>
        Assert.False(WindowsServicePathTrustInspector.IsOnLocalStorage(path));

    /// <summary>
    /// A path that is not rooted cannot be reasoned about: which machine, which volume, relative to
    /// what working directory. Refusing is the only answer that is not a guess.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    [InlineData(@"WinSight\service.exe")]
    [InlineData(@"..\..\service.exe")]
    public void AnUnrootedPathIsNotOnLocalStorage(string? path) =>
        Assert.False(WindowsServicePathTrustInspector.IsOnLocalStorage(path));

    /// <summary>
    /// The ordinary case must keep working. A local fixed-disk path is exactly where the service
    /// lives, and a check that refused it would stop the product installing.
    /// </summary>
    [Theory]
    [InlineData(@"C:\ProgramData\WinSight\winsight-firewall-service.exe")]
    [InlineData(@"C:\Program Files\WinSight\winsight.exe")]
    [InlineData(@"C:\")]
    public void ALocalPathIsOnLocalStorage(string path) =>
        Assert.True(WindowsServicePathTrustInspector.IsOnLocalStorage(path));

    /// <summary>
    /// A drive letter this machine does not have is not proof of anything, and turning an
    /// unrecognised root into a refusal would mean a service that will not start for a reason
    /// nobody can act on. The syntactic test above already covers the case that matters.
    /// </summary>
    [Fact]
    public void AnUnknownDriveLetterIsNotRefusedOnThatBasisAlone()
    {
        var unused = Enumerable.Range('D', 'Z' - 'D' + 1)
            .Select(letter => $"{(char)letter}:\\")
            .FirstOrDefault(root => !Directory.Exists(root));

        if (unused is null)
        {
            // Every letter in use is possible, and is not a failure of the code under test.
            return;
        }
        Assert.True(WindowsServicePathTrustInspector.IsOnLocalStorage(unused + @"WinSight\x.exe"));
    }

    /// <summary>
    /// End to end: the inspector declines a UNC executable with the refusal that names the reason,
    /// not with a generic inspection failure - an operator reading a log needs to know the check
    /// refused rather than broke.
    /// </summary>
    [Fact]
    public void TheInspectorRefusesAUncExecutableByName()
    {
        var inspector = new WindowsServicePathTrustInspector();

        var decision = inspector.InspectExecutable(@"\\server\share\winsight-firewall-service.exe");

        Assert.False(decision.IsTrusted);
        Assert.Equal(PathTrustCode.NotOnLocalStorage, decision.Code);
        Assert.Equal(
            ServicePathTrustDiagnosticCodes.NotOnLocalStorage,
            ServicePathTrustDiagnosticCodes.ForInstallDenial(decision.Code));
    }
}
