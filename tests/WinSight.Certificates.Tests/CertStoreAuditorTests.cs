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

    private static TrustedCertificate Root(bool hasPrivateKey, string sigAlg, int keyBits, bool isRsa) =>
        new(
            Store: "LocalMachine\\Root",
            Subject: "CN=Test Root",
            Issuer: "CN=Test Root",
            Thumbprint: "0000000000000000000000000000000000000000",
            SignatureAlgorithm: sigAlg,
            KeyBits: keyBits,
            IsRsa: isRsa,
            HasPrivateKey: hasPrivateKey,
            NotAfter: new DateTime(2040, 1, 1));
}
