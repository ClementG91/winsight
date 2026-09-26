using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WinSight.Core;

namespace WinSight.Certificates;

/// <summary>
/// Reads the certificate stores that grant or withdraw trust - <c>Root</c>, <c>TrustedPublisher</c>
/// and <c>Disallowed</c>, machine and user - and reduces each entry to a
/// <see cref="TrustedCertificate"/> so the audit can flag rogue-trust signals.
/// Read-only: opens each store read-only and never modifies trust.
/// </summary>
/// <remarks>
/// <c>CA</c> (intermediate authorities) is deliberately not read: an intermediate grants no trust of
/// its own - it needs a root - and the store holds hundreds of certificates Windows Update caches,
/// which would bury the entries that matter (WS-55).
/// </remarks>
public sealed class CertStoreAuditor
{
    private static readonly (StoreName Name, string Label, CertificateTrustRole Role)[] Stores =
    {
        (StoreName.Root, "Root", CertificateTrustRole.Root),
        (StoreName.TrustedPublisher, "TrustedPublisher", CertificateTrustRole.TrustedPublisher),
        (StoreName.Disallowed, "Disallowed", CertificateTrustRole.Disallowed),
    };

    public IReadOnlyList<TrustedCertificate> Snapshot() => SnapshotWithCoverage().Items;

    public AcquisitionSnapshot<TrustedCertificate> SnapshotWithCoverage()
    {
        var results = new List<TrustedCertificate>();
        var unreadableStores = 0;
        var unreadableCertificates = 0;
        // Computed before the walk so each CurrentUser root can be told apart from the machine
        // roots Windows merges into that same view. An empty set means the machine store could not
        // be read, and the audit then makes no user-installed claim at all rather than declaring
        // every public root user-installed.
        var userInstalledRoots = UserInstalledRoots.Thumbprints;
        foreach (var (name, label, role) in Stores)
        {
            // Machine first: its thumbprints are what the user view is de-duplicated against.
            var machineEntries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var machineRead = false;
            foreach (var location in new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser })
            {
                using var store = new X509Store(name, location);
                try
                {
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                }
                catch (Exception ex) when (ex is CryptographicException
                                             or UnauthorizedAccessException
                                             or System.Security.SecurityException)
                {
                    // A store that was never created is empty, not unreadable.
                    if (!IsMissingStore(ex))
                    {
                        unreadableStores++;
                    }
                    continue;
                }
                machineRead |= location == StoreLocation.LocalMachine;

                foreach (var cert in store.Certificates)
                {
                    using (cert)
                    {
                        try
                        {
                            if (location == StoreLocation.CurrentUser
                                && IsMergedMachineRoot(cert.Thumbprint, machineEntries))
                            {
                                continue;
                            }
                            if (location == StoreLocation.LocalMachine && cert.Thumbprint is { Length: > 0 } machine)
                            {
                                machineEntries.Add(machine);
                            }
                            var userOnly = location == StoreLocation.CurrentUser && role switch
                            {
                                CertificateTrustRole.Root => cert.Thumbprint is { Length: > 0 } thumbprint
                                    && userInstalledRoots.Contains(thumbprint),
                                // Only a claim the machine view could have contradicted.
                                CertificateTrustRole.TrustedPublisher => machineRead,
                                _ => false,
                            };
                            results.Add(Describe(cert, $"{location}\\{label}", userOnly, role));
                        }
                        catch (Exception ex) when (ex is CryptographicException
                                                     or NotSupportedException)
                        {
                            unreadableCertificates++;
                        }
                    }
                }
            }
        }
        return new AcquisitionSnapshot<TrustedCertificate>(
            results, unreadableStores, unreadableCertificates);
    }

    // CRYPT_E_NOT_FOUND / ERROR_FILE_NOT_FOUND: OpenExistingOnly on a store nobody created.
    private static bool IsMissingStore(Exception ex) =>
        ex is CryptographicException { HResult: unchecked((int)0x80092004) or unchecked((int)0x80070002) };
    /// <summary>
    /// Whether an entry of the current user's view of <c>Root</c> is a machine root Windows merged
    /// into it, already reported under <c>LocalMachine\Root</c>.
    /// </summary>
    /// <remarks>
    /// Reading both stores reported every machine root twice, doubling the list and its counts. The
    /// user view now contributes only what the user alone trusts. When the machine store could not
    /// be read, <paramref name="machineRoots"/> is empty, nothing is known to be merged, and the user
    /// view is reported whole.
    /// </remarks>
    internal static bool IsMergedMachineRoot(string? thumbprint, IReadOnlySet<string> machineRoots)
    {
        ArgumentNullException.ThrowIfNull(machineRoots);
        return !string.IsNullOrEmpty(thumbprint) && machineRoots.Contains(thumbprint);
    }

    private static TrustedCertificate Describe(X509Certificate2 cert, string store, bool userInstalled, CertificateTrustRole role)
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
            string.Equals(cert.Subject, cert.Issuer, StringComparison.Ordinal),
            cert.NotAfter,
            userInstalled,
            role);
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
            // Unreadable key, report as unknown rather than fail the whole scan.
        }
        return (0, false);
    }
}
