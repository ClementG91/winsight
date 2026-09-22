using Xunit;

namespace WinSight.Certificates.Tests;

/// <summary>
/// WS-55. Only <c>Root</c> was read. <c>TrustedPublisher</c> lets code signed by a publisher run
/// without the prompts other signed code gets, and its user view takes an entry from any program
/// with no elevation; <c>Disallowed</c> is what the machine explicitly distrusts.
/// </summary>
public sealed class TrustStoreRoleTests
{
    private static TrustedCertificate Entry(
        CertificateTrustRole role, bool userInstalled = false, bool hasPrivateKey = false,
        string sigAlg = "sha256RSA", int keyBits = 2048, bool isSelfSigned = false) =>
        new(
            Store: $"CurrentUser\\{role}",
            Subject: "CN=Contoso Code Signing",
            Issuer: isSelfSigned ? "CN=Contoso Code Signing" : "CN=Contoso CA",
            Thumbprint: "1111111111111111111111111111111111111111",
            SignatureAlgorithm: sigAlg,
            KeyBits: keyBits,
            IsRsa: true,
            HasPrivateKey: hasPrivateKey,
            IsSelfSigned: isSelfSigned,
            NotAfter: new DateTime(2040, 1, 1),
            IsUserInstalled: userInstalled,
            Role: role);

    [Fact]
    public void AUserOnlyTrustedPublisherIsFlagged()
    {
        var publisher = Entry(CertificateTrustRole.TrustedPublisher, userInstalled: true);

        Assert.True(publisher.Notable);
        Assert.Contains(publisher.Risks, risk => risk.Contains("trusted publisher for this user only", StringComparison.Ordinal));
    }

    [Fact]
    public void AMachineTrustedPublisherWithAnOldSignatureIsNotNoise()
    {
        // A publisher certificate is a leaf: SHA-1 is common there and grants nothing by itself.
        Assert.False(Entry(CertificateTrustRole.TrustedPublisher, sigAlg: "sha1RSA").Notable);
    }

    [Fact]
    public void ATrustedPublisherWhosePrivateKeyIsHereIsFlagged() =>
        Assert.Contains(Entry(CertificateTrustRole.TrustedPublisher, hasPrivateKey: true).Risks,
            risk => risk.Contains("can sign code it trusts", StringComparison.Ordinal));

    [Theory]
    [InlineData(true, true, "sha1RSA", 1024)]
    [InlineData(false, false, "md5RSA", 512)]
    public void ADistrustEntryIsNeverAFinding(bool userInstalled, bool hasPrivateKey, string sigAlg, int keyBits) =>
        Assert.Empty(Entry(CertificateTrustRole.Disallowed, userInstalled, hasPrivateKey, sigAlg, keyBits).Risks);

    [Fact]
    public void RootsKeepTheirRules()
    {
        var root = Entry(CertificateTrustRole.Root, userInstalled: true) with { Store = "CurrentUser\\Root" };

        Assert.Contains(root.Risks, risk => risk.Contains("a root an unprivileged program can install", StringComparison.Ordinal));
        Assert.Contains(Entry(CertificateTrustRole.Root, sigAlg: "sha1RSA").Risks, risk => risk.Contains("weak signature", StringComparison.Ordinal));
    }

    [Fact]
    public void TheLiveSnapshotLabelsEachEntryWithItsStoreAndRole()
    {
        var entries = new CertStoreAuditor().Snapshot();

        Assert.Contains(entries, e => e.Role == CertificateTrustRole.Root);
        foreach (var entry in entries)
        {
            Assert.EndsWith($"\\{entry.Role}", entry.Store, StringComparison.Ordinal);
            if (entry.Role == CertificateTrustRole.Disallowed)
            {
                Assert.False(entry.Notable);
            }
            if (entry.Store.StartsWith("LocalMachine", StringComparison.Ordinal))
            {
                Assert.False(entry.IsUserInstalled);
            }
        }
        // The user view merges the machine's entries; each thumbprint appears once per store.
        Assert.All(entries.GroupBy(e => (e.Role, e.Thumbprint)), group => Assert.Single(group));
    }
}
