using WinSight.Core;
using Xunit;

namespace WinSight.Core.Tests;

/// <summary>
/// Whether the signing certificate's revocation status was actually established.
/// </summary>
/// <remarks>
/// <b>The fact that was being discarded.</b> Revocation runs cache-only, so nothing leaves the
/// machine during a scan - a deliberate choice and the right one. The consequence is that on a
/// machine with no cached CRL or OCSP response Windows reports the check as undetermined, and
/// <c>MapResult</c> maps that to trusted, because refusing to trust ordinary signed software on
/// every offline machine would be a false accusation against most of Windows.
///
/// That mapping is correct, and in making it the verifier threw away the one fact an investigator
/// chasing a stolen certificate needs. Campaigns using stolen signing keys run for months past the
/// revocation, and "signature valid" is exactly what those binaries produce. "Valid" and "valid,
/// and revocation was never established" now stop reading identically.
/// </remarks>
public sealed class RevocationStandingTests
{
    [Fact]
    public void SuccessMeansCheckedAndNotRevoked() =>
        Assert.Equal(RevocationStanding.NotRevoked, NativeSignatureVerifier.MapRevocation(0));

    [Fact]
    public void ARevokedCertificateIsReportedAsRevoked() =>
        Assert.Equal(
            RevocationStanding.Revoked, NativeSignatureVerifier.MapRevocation(0x800B010C));

    /// <summary>
    /// The three codes that mean "nothing cached to answer from". They map to a trusted signature -
    /// which is what keeps offline machines honest - and must record that the check did not run.
    /// </summary>
    [Theory]
    [InlineData(0x800B010Eu)] // CERT_E_REVOCATION_FAILURE
    [InlineData(0x80092012u)] // CRYPT_E_NO_REVOCATION_CHECK
    [InlineData(0x80092013u)] // CRYPT_E_REVOCATION_OFFLINE
    public void AnUnestablishedCheckIsRecordedAsSuch(uint result)
    {
        Assert.Equal(RevocationStanding.NotChecked, NativeSignatureVerifier.MapRevocation(result));
        // The mapping these codes have always had, which this must not disturb: they are not
        // evidence against the file.
        Assert.Equal(SignatureState.SignedTrusted, NativeSignatureVerifier.MapResult(result));
    }

    /// <summary>
    /// A verdict about the signature itself says nothing either way about revocation, and claiming
    /// otherwise would put a fact in the report that was never established.
    /// </summary>
    [Theory]
    [InlineData(0x80096010u)] // TRUST_E_BAD_DIGEST
    [InlineData(0x800B0109u)] // CERT_E_UNTRUSTEDROOT
    [InlineData(0x800B0100u)] // TRUST_E_NOSIGNATURE
    [InlineData(0xDEADBEEFu)] // anything unrecognised
    public void AVerdictAboutTheSignatureSaysNothingAboutRevocation(uint result) =>
        Assert.Equal(
            RevocationStanding.Unspecified, NativeSignatureVerifier.MapRevocation(result));

    /// <summary>
    /// The triage hint reads like its neighbour: true only when trust was established and the
    /// revocation question was not answered.
    /// </summary>
    [Fact]
    public void TheHintIsTrueOnlyForATrustedButUncheckedSignature()
    {
        var unchecked_ = new SignatureVerdict(
            SignatureState.SignedTrusted, "CN=Contoso",
            SignatureTrustAnchor.MachineRoot, RevocationStanding.NotChecked);
        var confirmed = new SignatureVerdict(
            SignatureState.SignedTrusted, "CN=Contoso",
            SignatureTrustAnchor.MachineRoot, RevocationStanding.NotRevoked);
        var untrusted = new SignatureVerdict(
            SignatureState.SignedUntrusted, "CN=Contoso",
            SignatureTrustAnchor.Unspecified, RevocationStanding.NotChecked);

        Assert.True(unchecked_.TrustedWithoutRevocationCheck);
        Assert.False(confirmed.TrustedWithoutRevocationCheck);
        Assert.False(untrusted.TrustedWithoutRevocationCheck);
    }

    /// <summary>
    /// Every existing construction site keeps working: the parameter is optional and defaults to
    /// saying nothing, which is the correct answer for a verifier that does not establish it.
    /// </summary>
    [Fact]
    public void AVerdictBuiltWithoutTheParameterClaimsNothing()
    {
        Assert.Equal(RevocationStanding.Unspecified, SignatureVerdict.Unknown.Revocation);
        Assert.Equal(RevocationStanding.Unspecified, SignatureVerdict.Unsigned.Revocation);
        Assert.Equal(
            RevocationStanding.Unspecified,
            new SignatureVerdict(SignatureState.SignedTrusted, "CN=X").Revocation);
    }
}
