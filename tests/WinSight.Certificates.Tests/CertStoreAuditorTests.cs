using Xunit;

namespace WinSight.Certificates.Tests;

public sealed class CertStoreAuditorTests
{
    [Theory]
    [InlineData("md5RSA", true)]
    [InlineData("sha1RSA", true)]
    [InlineData("md2RSA", true)]
    [InlineData("sha256RSA", false)]
    [InlineData("sha384ECDSA", false)]
    public void WeakSignature_IsDetectedForBrokenAlgorithms(string algorithm, bool weak) =>
        Assert.Equal(weak, TrustedCertificate.IsWeakSignature(algorithm));

    [Fact]
    public void Risks_PrivateKeyOnTrustedRoot_IsFlagged()
    {
        var cert = Root(hasPrivateKey: true, sigAlg: "sha256RSA", keyBits: 4096, isRsa: true);
        Assert.True(cert.Notable);
        Assert.Contains(cert.Risks, r => r.Contains("private key"));
    }

    [Fact]
    public void Risks_UndersizedRsaKey_IsFlagged()
    {
        var cert = Root(hasPrivateKey: false, sigAlg: "sha256RSA", keyBits: 1024, isRsa: true);
        Assert.Contains(cert.Risks, r => r.Contains("1024-bit"));
    }

    [Fact]
    public void Risks_SmallEccKey_IsNotFlaggedAsUndersized()
    {
        // 256-bit ECC is strong — the small-key rule is RSA-only.
        var cert = Root(hasPrivateKey: false, sigAlg: "sha256ECDSA", keyBits: 256, isRsa: false);
        Assert.False(cert.Notable);
    }

    [Fact]
    public void Risks_CleanModernRoot_HasNoRisks()
    {
        var cert = Root(hasPrivateKey: false, sigAlg: "sha256RSA", keyBits: 4096, isRsa: true);
        Assert.Empty(cert.Risks);
        Assert.False(cert.Notable);
    }

    [Fact]
    public void Risks_Sha1SelfSignedRoot_IsNotFlagged()
    {
        // The common, benign case: nearly every established public root (DigiCert,
        // Baltimore, Comodo…) is SHA-1 self-signed. A root's own signature is not a
        // trust input, so this must NOT be flagged — it was a mass false positive.
        var cert = Root(hasPrivateKey: false, sigAlg: "sha1RSA", keyBits: 2048, isRsa: true, isSelfSigned: true);
        Assert.False(cert.Notable);
        Assert.Empty(cert.Risks);
    }

    [Fact]
    public void Risks_Sha1NonSelfSignedCertInRootStore_IsFlagged()
    {
        // A weak-signature cert that is NOT self-signed sitting in the root store is
        // genuinely odd (an intermediate masquerading as a root) — still flagged.
        var cert = Root(hasPrivateKey: false, sigAlg: "sha1RSA", keyBits: 2048, isRsa: true, isSelfSigned: false);
        Assert.True(cert.Notable);
        Assert.Contains(cert.Risks, r => r.Contains("weak signature"));
    }

    [Fact]
    public void Snapshot_ReadsTrustedRoots_WithValidShape()
    {
        // A real Windows host always ships trusted roots (Microsoft, DigiCert, …).
        var certs = new CertStoreAuditor().Snapshot();
        Assert.NotEmpty(certs);
        Assert.All(certs, c =>
        {
            Assert.False(string.IsNullOrWhiteSpace(c.Subject));
            Assert.False(string.IsNullOrWhiteSpace(c.Thumbprint));
        });
    }

    private static TrustedCertificate Root(
        bool hasPrivateKey, string sigAlg, int keyBits, bool isRsa, bool isSelfSigned = true) =>
        new(
            Store: "LocalMachine\\Root",
            Subject: "CN=Test Root",
            Issuer: isSelfSigned ? "CN=Test Root" : "CN=Some Other CA",
            Thumbprint: "0000000000000000000000000000000000000000",
            SignatureAlgorithm: sigAlg,
            KeyBits: keyBits,
            IsRsa: isRsa,
            HasPrivateKey: hasPrivateKey,
            IsSelfSigned: isSelfSigned,
            NotAfter: new DateTime(2040, 1, 1));
}
