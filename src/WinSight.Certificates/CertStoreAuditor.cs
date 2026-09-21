using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WinSight.Core;

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

    public IReadOnlyList<TrustedCertificate> Snapshot() => SnapshotWithCoverage().Items;

    public AcquisitionSnapshot<TrustedCertificate> SnapshotWithCoverage()
    {
        var results = new List<TrustedCertificate>();
        var unreadableStores = 0;
        var unreadableCertificates = 0;
        // Computed before the walk so each CurrentUser entry can be told apart from the machine
        // roots Windows merges into that same view. An empty set means the machine store could not
        // be read, and the audit then makes no user-installed claim at all rather than declaring
        // every public root user-installed.
        var userInstalled = UserInstalledRoots.Thumbprints;
        var machineRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, location, label) in Stores)
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
                unreadableStores++;
                continue;
            }

            foreach (var cert in store.Certificates)
            {
                using (cert)
                {
                    try
                    {
                        if (location == StoreLocation.CurrentUser
                            && IsMergedMachineRoot(cert.Thumbprint, machineRoots))
                        {
                            continue;
                        }
                        if (location == StoreLocation.LocalMachine && cert.Thumbprint is { Length: > 0 } machine)
                        {
                            machineRoots.Add(machine);
                        }
                        results.Add(Describe(
                            cert,
                            label,
                            cert.Thumbprint is { Length: > 0 } thumbprint
                                && userInstalled.Contains(thumbprint)));
                    }
                    catch (Exception ex) when (ex is CryptographicException
                                                 or NotSupportedException)
                    {
                        unreadableCertificates++;
                    }
                }
            }
        }
        return new AcquisitionSnapshot<TrustedCertificate>(
            results, unreadableStores, unreadableCertificates);
    }

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

    private static TrustedCertificate Describe(X509Certificate2 cert, string store, bool userInstalled)
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
            userInstalled);
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
