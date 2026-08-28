using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WinSight.Core;

/// <summary>
/// The signature standing of a binary that lives inside an installed MSIX/AppX package.
/// </summary>
/// <remarks>
/// <b>Why a packaged binary needs its own answer.</b> An MSIX package is signed once, as a package:
/// the catalogue of every file's hash is in <c>AppxBlockMap.xml</c> and the signature over it is in
/// <c>AppxSignature.p7x</c>. The individual executables inside usually carry no embedded Authenticode
/// signature and appear in no catalog — Windows itself reports <c>NotSigned</c> for
/// <c>WindowsApps\Microsoft.Paint_…\PaintApp\mspaint.exe</c>. So the embedded-then-catalog chain
/// reached the end of its options and concluded <c>Unsigned</c>, which is literally true of the file
/// and materially false about the software: every Store application on the machine read as unsigned,
/// including Microsoft's own.
///
/// <b>What is verified, and what is not.</b> The package signature is decoded and its signer chain
/// is validated to a trusted root. The per-file block-map hash is <i>not</i> recomputed, so this
/// says "this file belongs to a package signed by X", not "this file is unmodified". That is a
/// weaker statement than an Authenticode verdict and it is deliberately reported as such through the
/// signer name rather than being dressed up: Windows will not run a tampered file from a packaged
/// application anyway, because the block map is enforced at load time by the OS.
///
/// <b>No network.</b> Chain building has certificate downloads and revocation disabled, matching the
/// promise the rest of the verifier keeps.
/// </remarks>
public static class MsixPackageSignature
{
    private const string SignatureFile = "AppxSignature.p7x";

    // "PKCX" - the four bytes an AppxSignature.p7x carries before the DER PKCS#7 blob.
    private static readonly byte[] P7xMagic = [0x50, 0x4B, 0x43, 0x58];

    /// <summary>Deepest package root at or above <paramref name="path"/>, or null if there is none.</summary>
    /// <remarks>
    /// Identified by the presence of the signature file rather than by matching
    /// <c>Program Files\WindowsApps</c>, so sideloaded and per-user packages are covered too and a
    /// directory that merely resembles the layout is not mistaken for one.
    /// </remarks>
    public static string? FindPackageRoot(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }
        try
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(path));
            // Bounded walk: a package is a handful of levels deep, and an unbounded one on a
            // pathological path is a cost this pays per file.
            for (var depth = 0; depth < 16 && !string.IsNullOrEmpty(directory); depth++)
            {
                if (File.Exists(Path.Combine(directory, SignatureFile)))
                {
                    return directory;
                }
                directory = Path.GetDirectoryName(directory);
            }
        }
        catch (Exception ex) when (ex is ArgumentException
                                     or NotSupportedException
                                     or PathTooLongException
                                     or IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            return null;
        }
        return null;
    }

    /// <summary>
    /// The verdict for a file inside a package, or null when it is not in one or the package
    /// signature could not be read. Null means "no opinion", never "unsigned".
    /// </summary>
    public static SignatureVerdict? Verify(string? path)
    {
        var root = FindPackageRoot(path);
        if (root is null)
        {
            return null;
        }

        byte[] blob;
        try
        {
            blob = File.ReadAllBytes(Path.Combine(root, SignatureFile));
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            // A package whose signature cannot be read is undetermined, which is exactly what
            // SignatureState.Unknown is for.
            return SignatureVerdict.Unknown;
        }

        if (blob.Length <= P7xMagic.Length || !blob.AsSpan(0, P7xMagic.Length).SequenceEqual(P7xMagic))
        {
            return SignatureVerdict.Unknown;
        }

        try
        {
            // X509Certificate2Collection reads PKCS#7 directly, so no additional cryptography
            // dependency enters a project whose whole supply chain is attested per release.
            // X509CertificateLoader, which supersedes this for single certificates, has no PKCS#7
            // collection equivalent; the same suppression is already used by SignerOf for the same
            // reason.
            var certificates = new X509Certificate2Collection();
#pragma warning disable SYSLIB0057
            certificates.Import(blob.AsSpan(P7xMagic.Length).ToArray());
#pragma warning restore SYSLIB0057
            if (LeafOf(certificates) is not { } signer)
            {
                return SignatureVerdict.Unknown;
            }

            using (signer)
            {
                var trusted = ChainIsTrusted(signer, certificates);
                return new SignatureVerdict(
                    trusted ? SignatureState.SignedTrusted : SignatureState.SignedUntrusted,
                    $"{signer.Subject} (MSIX package)",
                    trusted && UserInstalledRoots.TrustsAUserInstalledRoot(path!)
                        ? SignatureTrustAnchor.UserInstalledRoot
                        : trusted ? SignatureTrustAnchor.MachineRoot : SignatureTrustAnchor.Unspecified);
            }
        }
        catch (CryptographicException)
        {
            return SignatureVerdict.Unknown;
        }
    }

    /// <summary>
    /// The end-entity certificate in a PKCS#7 blob: the one that issued nothing else in it.
    /// </summary>
    /// <remarks>
    /// A package signature carries the signer plus its chain. Reading the collection in file order
    /// would sometimes name an intermediate as the publisher, which is a wrong name beside a
    /// security verdict; the leaf is the one no other certificate in the set was issued by.
    /// </remarks>
    private static X509Certificate2? LeafOf(X509Certificate2Collection certificates)
    {
        X509Certificate2? leaf = null;
        foreach (var certificate in certificates)
        {
            var isIssuerOfAnother = certificates.Any(other =>
                !ReferenceEquals(other, certificate)
                && string.Equals(
                    other.IssuerName.Name, certificate.SubjectName.Name, StringComparison.OrdinalIgnoreCase));
            if (!isIssuerOfAnother)
            {
                leaf = certificate;
                break;
            }
        }
        // A single self-signed certificate issues nothing and is still the signer.
        return leaf ?? (certificates.Count > 0 ? certificates[0] : null);
    }

    /// <param name="carried">
    /// Every certificate the package signature shipped, offered to the chain builder as an extra
    /// store.
    /// </param>
    /// <remarks>
    /// The intermediates must come from the blob. Certificate downloads are disabled - the product
    /// promises a single outbound path and this is not it - so a chain built from the leaf alone
    /// cannot reach the root, and every MSIX package would be reported as signed-but-untrusted.
    /// Which is exactly what happened before this parameter existed: Microsoft's own Store
    /// applications came back with an invalid signature.
    /// </remarks>
    private static bool ChainIsTrusted(X509Certificate2 signer, X509Certificate2Collection carried)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.ExtraStore.AddRange(carried);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        // A package signature outlives its signing certificate, exactly as Authenticode does with a
        // timestamp; refusing an expired signer would flag every application older than its cert.
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid
            | X509VerificationFlags.IgnoreCtlNotTimeValid;
        return chain.Build(signer);
    }
}
