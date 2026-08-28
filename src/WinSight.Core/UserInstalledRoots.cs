using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WinSight.Core;

/// <summary>
/// Which trusted roots on this machine were put there by a user rather than by Windows, and whether
/// a given signed file owes its trust to one of them.
/// </summary>
/// <remarks>
/// <b>The gap this closes.</b> <c>WinVerifyTrust</c> runs the default policy, which consults
/// <c>CurrentUser\Root</c> — a store any account writes without elevation. Import a self-signed
/// RSA-4096/SHA-256 root there, sign an implant with a leaf issued by it, and every WinSight verdict
/// reads <c>SignatureValid</c>. The verdict model had no way to say otherwise: <c>SignedTrusted</c>
/// meant "the chain reached a trusted root" and nothing more, so the product's central claim was
/// defeated by an unprivileged registry-and-store write. The certificate audit did not catch it
/// either — it flagged private keys, weak signatures and short RSA keys, and a fresh strong
/// self-signed root has none of those.
///
/// <b>Why membership, not the CTL.</b> Windows' root program updates land in
/// <c>LocalMachine\Root</c>. Enumerating <c>CurrentUser\Root</c> returns the merged view, so a
/// thumbprint present there and absent from the machine store is, by construction, one this user
/// added. That needs no network, no shipped CTL copy, and cannot go stale.
///
/// <b>It costs nothing on a healthy machine.</b> The per-file chain walk runs only when at least one
/// user-installed root exists. On a machine with none — the normal case — <see cref="Any"/> is false
/// and no file is ever chained, so the check adds a single store read to a whole scan.
/// </remarks>
public static class UserInstalledRoots
{
    private static readonly Lazy<IReadOnlySet<string>> Cached =
        new(Load, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>SHA-1 thumbprints of roots trusted for this user but not machine-wide.</summary>
    public static IReadOnlySet<string> Thumbprints => Cached.Value;

    /// <summary>True when this machine has at least one user-installed trusted root.</summary>
    public static bool Any => Cached.Value.Count > 0;

    /// <summary>
    /// Whether <paramref name="path"/>'s Authenticode chain terminates in a user-installed root.
    /// </summary>
    /// <remarks>
    /// Answers <see langword="false"/> whenever it cannot tell — an unreadable file, a chain that
    /// does not build, a signature it cannot parse. This flag downgrades trust, so an unproven
    /// "yes" would be a false accusation against ordinary signed software.
    /// </remarks>
    public static bool TrustsAUserInstalledRoot(string path)
    {
        if (!Any || string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        try
        {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile remains the only Authenticode leaf reader.
            using var leaf = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            using var chain = new X509Chain();
            // No network, ever: WinSight promises the VirusTotal lookup is its only outbound path,
            // and a chain build will otherwise fetch AIA and CRL material.
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            // The question is which root the chain reaches, not whether the chain is valid — an
            // expired or otherwise imperfect chain still tells us where its trust came from.
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid
                | X509VerificationFlags.IgnoreCtlNotTimeValid
                | X509VerificationFlags.IgnoreCtlSignerRevocationUnknown
                | X509VerificationFlags.IgnoreEndRevocationUnknown
                | X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown
                | X509VerificationFlags.IgnoreRootRevocationUnknown;

            _ = chain.Build(leaf);
            if (chain.ChainElements.Count == 0)
            {
                return false;
            }
            var root = chain.ChainElements[^1].Certificate;
            return root.Thumbprint is { Length: > 0 } thumbprint
                && Cached.Value.Contains(thumbprint);
        }
        catch (Exception ex) when (ex is CryptographicException
                                     or IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            return false;
        }
    }

    /// <summary>
    /// Recomputes the index. Only for tests: the set is cached because a scan asks about it once
    /// per file and the stores do not change underneath a running scan.
    /// </summary>
    internal static IReadOnlySet<string> Load()
    {
        var machine = ReadThumbprints(StoreLocation.LocalMachine);
        var user = ReadThumbprints(StoreLocation.CurrentUser);
        // A store WinSight could not read yields an empty set. Subtracting an empty machine set
        // from a populated user set would declare every public root user-installed, so a failure to
        // read the machine store means no claim at all rather than a machine-wide false accusation.
        if (machine.Count == 0)
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }
        user.ExceptWith(machine);
        return user;
    }

    private static HashSet<string> ReadThumbprints(StoreLocation location)
    {
        var thumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using var store = new X509Store(StoreName.Root, location);
        try
        {
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        }
        catch (Exception ex) when (ex is CryptographicException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            return thumbprints;
        }

        foreach (var certificate in store.Certificates)
        {
            using (certificate)
            {
                if (certificate.Thumbprint is { Length: > 0 } thumbprint)
                {
                    thumbprints.Add(thumbprint);
                }
            }
        }
        return thumbprints;
    }
}
