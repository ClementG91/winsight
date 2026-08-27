using WinSight.Core;
using Xunit;

namespace WinSight.Core.Tests;

/// <summary>
/// The two halves of the trust model that a signature verdict alone could not express: which root
/// it rests on, and whether revocation was consulted at all.
/// </summary>
public sealed class TrustAnchorTests
{
    /// <summary>
    /// "Signed and trusted" is worth no more than the root it chains to. WinVerifyTrust consults
    /// <c>CurrentUser\Root</c>, which any account writes with no elevation, so the verdict has to
    /// carry the anchor or an implant signed beneath an imported root reads exactly like Microsoft.
    /// </summary>
    [Fact]
    public void ATrustedVerdictOnAUserInstalledRootIsMarkedAsSuch()
    {
        var verdict = new SignatureVerdict(
            SignatureState.SignedTrusted, "CN=Anything", SignatureTrustAnchor.UserInstalledRoot);

        Assert.True(verdict.IsSigned);
        Assert.True(verdict.RestsOnUserInstalledTrust);
    }

    [Theory]
    [InlineData(SignatureState.SignedTrusted, SignatureTrustAnchor.MachineRoot)]
    [InlineData(SignatureState.SignedTrusted, SignatureTrustAnchor.Unspecified)]
    [InlineData(SignatureState.Unsigned, SignatureTrustAnchor.UserInstalledRoot)]
    [InlineData(SignatureState.SignedUntrusted, SignatureTrustAnchor.UserInstalledRoot)]
    public void EverythingElseMakesNoUserRootClaim(SignatureState state, SignatureTrustAnchor anchor) =>
        Assert.False(new SignatureVerdict(state, null, anchor).RestsOnUserInstalledTrust);

    /// <summary>
    /// The default keeps every existing construction site source-compatible and, more importantly,
    /// silent: a verdict built without an anchor must never assert one.
    /// </summary>
    [Fact]
    public void TheAnchorDefaultsToNoClaim()
    {
        Assert.Equal(SignatureTrustAnchor.Unspecified, new SignatureVerdict(SignatureState.SignedTrusted, "x").Anchor);
        Assert.Equal(SignatureTrustAnchor.Unspecified, SignatureVerdict.Unknown.Anchor);
        Assert.Equal(SignatureTrustAnchor.Unspecified, SignatureVerdict.Unsigned.Anchor);
        Assert.Equal(SignatureTrustAnchor.Unspecified, SignatureVerdict.Missing.Anchor);
    }

    /// <summary>
    /// Revocation was previously switched off twice over - WTD_REVOKE_NONE alongside
    /// WTD_REVOCATION_CHECK_NONE - which made this branch unreachable code while stolen signing
    /// certificates kept verifying for months after revocation.
    /// </summary>
    [Fact]
    public void ARevokedCertificateIsNotTrusted() =>
        Assert.Equal(SignatureState.SignedUntrusted, NativeSignatureVerifier.MapResult(0x800B010C));

    /// <summary>
    /// The counterpart risk of turning revocation on: with cache-only retrieval, a machine holding
    /// no cached CRL reports the check as undetermined. Mapping those to null would defer a
    /// genuinely embedded-signed file to the catalog verifier, which has no entry for it, and the
    /// file would be reported UNSIGNED - a false accusation against ordinary software on every
    /// offline machine.
    /// </summary>
    [Theory]
    [InlineData(0x800B010Eu)] // CERT_E_REVOCATION_FAILURE
    [InlineData(0x80092012u)] // CRYPT_E_NO_REVOCATION_CHECK
    [InlineData(0x80092013u)] // CRYPT_E_REVOCATION_OFFLINE
    public void AnUndeterminedRevocationCheckDoesNotDowngradeAValidSignature(uint code) =>
        Assert.Equal(SignatureState.SignedTrusted, NativeSignatureVerifier.MapResult(code));

    [Theory]
    [InlineData(0x00000000u, SignatureState.SignedTrusted)]
    [InlineData(0x80096010u, SignatureState.SignedUntrusted)]
    [InlineData(0x800B0109u, SignatureState.SignedUntrusted)]
    public void TheEstablishedMappingsAreUnchanged(uint code, SignatureState expected) =>
        Assert.Equal(expected, NativeSignatureVerifier.MapResult(code));

    [Fact]
    public void AnUnrecognisedResultStillDefersToTheCatalog() =>
        Assert.Null(NativeSignatureVerifier.MapResult(0x800B0100));

    /// <summary>
    /// On a machine with no user-installed root the per-file chain walk must never run, which is
    /// what makes this check free on a healthy machine.
    /// </summary>
    [Fact]
    public void NoUserInstalledRootMeansNoFileIsEverChained()
    {
        if (UserInstalledRoots.Any)
        {
            // This machine has one, so the cheap path cannot be observed here. Assert the index is
            // at least self-consistent instead of skipping silently.
            Assert.NotEmpty(UserInstalledRoots.Thumbprints);
            return;
        }

        Assert.False(UserInstalledRoots.TrustsAUserInstalledRoot(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe")));
    }

    /// <summary>
    /// A root Windows ships is machine-wide, so it must never be counted as user-installed - that
    /// would flag every signed binary on the machine.
    /// </summary>
    [Fact]
    public void MachineRootsAreNeverCountedAsUserInstalled()
    {
        using var machine = new System.Security.Cryptography.X509Certificates.X509Store(
            System.Security.Cryptography.X509Certificates.StoreName.Root,
            System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine);
        machine.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);

        foreach (var certificate in machine.Certificates)
        {
            using (certificate)
            {
                Assert.DoesNotContain(certificate.Thumbprint, UserInstalledRoots.Thumbprints);
            }
        }
    }

    /// <summary>
    /// An unreadable path is not a finding. This flag downgrades trust, so an unproven "yes" would
    /// be a false accusation.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(@"C:\this\does\not\exist\at\all.exe")]
    public void AnUnreadableTargetMakesNoClaim(string path) =>
        Assert.False(UserInstalledRoots.TrustsAUserInstalledRoot(path));
}
