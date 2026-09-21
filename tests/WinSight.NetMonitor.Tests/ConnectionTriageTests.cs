using WinSight.Core;
using WinSight.NetMonitor;
using Xunit;

namespace WinSight.NetMonitor.Tests;

/// <summary>Which live connections the scan flags.</summary>
public sealed class ConnectionTriageTests
{
    private static Connection Established(SignatureVerdict signature, string remote = "93.184.216.34:443") =>
        new("TCP", "192.168.1.10:50000", remote, "ESTABLISHED", 1234, "thing.exe",
            @"C:\Users\me\AppData\Local\thing.exe", signature);

    [Theory]
    [InlineData(SignatureState.Unsigned)]
    [InlineData(SignatureState.SignedUntrusted)]
    [InlineData(SignatureState.Missing)]
    public void AnExternalConnectionFromAnUntrustedImageIsNoteworthy(SignatureState state) =>
        Assert.True(Established(new SignatureVerdict(state, null)).Noteworthy);

    /// <summary>
    /// An owner whose signature holds only through a root the user could have installed reads as
    /// validly signed; minting it takes no privilege, so it is flagged like an unsigned owner.
    /// </summary>
    [Fact]
    public void AnExternalConnectionFromAnImageTrustedOnlyThroughAUserRootIsNoteworthy() =>
        Assert.True(Established(new SignatureVerdict(
            SignatureState.SignedTrusted, "CN=Microsoft Windows", SignatureTrustAnchor.UserInstalledRoot)).Noteworthy);

    [Theory]
    [InlineData(SignatureTrustAnchor.MachineRoot)]
    [InlineData(SignatureTrustAnchor.Unspecified)]
    public void AnExternalConnectionFromAMachineTrustedImageIsNot(SignatureTrustAnchor anchor) =>
        Assert.False(Established(new SignatureVerdict(SignatureState.SignedTrusted, "CN=Vendor", anchor)).Noteworthy);

    [Fact]
    public void ALocalConnectionIsNotNoteworthyWhateverItsOwner() =>
        Assert.False(Established(
            new SignatureVerdict(SignatureState.SignedTrusted, "CN=x", SignatureTrustAnchor.UserInstalledRoot),
            remote: "127.0.0.1:8080").Noteworthy);
}
