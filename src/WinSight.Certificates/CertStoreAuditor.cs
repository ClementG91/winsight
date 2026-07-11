using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WinSight.Certificates;

/// <summary>
/// Reads the trusted-root certificate stores (machine + user) and reduces each entry
/// to a <see cref="TrustedCertificate"/> so the audit can flag rogue-CA signals.
/// Read-only: opens each store read-only and never modifies trust.
/// </summary>
public sealed class CertStoreAuditor
{
    private static readonly (StoreName Name, StoreLocation Location, string Label)[] Stores =
    {
        (StoreName.Root, StoreLocation.LocalMachine, "LocalMachine\\Root"),
        (StoreName.Root, StoreLocation.CurrentUser, "CurrentUser\\Root"),
    };

    public IReadOnlyList<TrustedCertificate> Snapshot()
    {
        var results = new List<TrustedCertificate>();
        foreach (var (name, location, label) in Stores)
        {
            using var store = new X509Store(name, location);
            try
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            }
            catch (CryptographicException)
            {
                // Store not present for this location — skip, don't guess.
                continue;
            }

            foreach (var cert in store.Certificates)
            {
                using (cert)
                {
                    results.Add(Describe(cert, label));
                }
            }
        }
        return results;
    }

    private static TrustedCertificate Describe(X509Certificate2 cert, string store)
    {
        var (keyBits, isRsa) = KeyInfo(cert);
        return new TrustedCertificate(
            store,
            cert.Subject,
            cert.Issuer,
            cert.Thumbprint,
            cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "unknown",
            keyBits,
            isRsa,
            cert.HasPrivateKey,
            cert.NotAfter);
    }

    private static (int Bits, bool IsRsa) KeyInfo(X509Certificate2 cert)
    {
        try
        {
            using var rsa = cert.GetRSAPublicKey();
            if (rsa is not null)
            {
                return (rsa.KeySize, true);
            }
            using var ecdsa = cert.GetECDsaPublicKey();
            if (ecdsa is not null)
            {
                return (ecdsa.KeySize, false);
            }
        }
        catch (CryptographicException)
        {
            // Unreadable key — report as unknown rather than fail the whole scan.
        }
        return (0, false);
    }
}
