using System.Security.Cryptography;

namespace WinSight.Core;

/// <summary>
/// The signature detail WinSight shows for one file: its Authenticode verdict plus the three
/// identification hashes a signature window (What's Your Sign?) and a VirusTotal lookup use. Built
/// out of process, so there is no in-process shell extension in every Explorer window.
/// </summary>
/// <param name="Path">The validated local file path.</param>
/// <param name="State">The Authenticode state.</param>
/// <param name="Signer">The signer subject, or null when unsigned.</param>
/// <param name="Anchor">Which trusted root a trusted verdict rests on.</param>
/// <param name="Revocation">Whether revocation was established.</param>
/// <param name="Md5">MD5 of the file bytes, for identification and VirusTotal lookup.</param>
/// <param name="Sha1">SHA-1 of the file bytes.</param>
/// <param name="Sha256">SHA-256 of the file bytes.</param>
public sealed record FileSignatureReport(
    string Path,
    SignatureState State,
    string? Signer,
    SignatureTrustAnchor Anchor,
    RevocationStanding Revocation,
    string? Md5,
    string? Sha1,
    string? Sha256)
{
    /// <summary>True when the verdict rests only on a root an unprivileged user could have installed.</summary>
    public bool RestsOnUserInstalledTrust =>
        State == SignatureState.SignedTrusted && Anchor == SignatureTrustAnchor.UserInstalledRoot;
}

/// <summary>
/// Builds a <see cref="FileSignatureReport"/> from a path: validate it as a local file, get its
/// Authenticode verdict from the shared verifier, and compute the identification hashes. Returns null
/// for anything that is not an ordinary local file, so a UNC or device argument never reaches here.
/// </summary>
public sealed class FileSignatureReporter
{
    private readonly ISignatureVerifier _verifier;

    public FileSignatureReporter(ISignatureVerifier verifier) =>
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));

    /// <summary>The report for <paramref name="rawPath"/>, or null when it is not an ordinary local file.</summary>
    public FileSignatureReport? Describe(string? rawPath, CancellationToken cancellationToken = default)
    {
        var path = SignaturePathGuard.LocalFileArgument(rawPath);
        if (path is null)
        {
            return null;
        }
        try
        {
            using var lease = AutomaticFileAccess.TryAcquire(path);
            if (lease is null || lease.IsDirectory)
            {
                return null;
            }
            // Keep one handle-bound object from before the trust decision until every displayed
            // hash has been computed. Reads use that acquired object; identity revalidation catches
            // Windows rename semantics that can replace the path entry despite a read-shared handle.
            using var stream = lease.OpenRead();
            var verdict = _verifier.Verify(lease.FullPath, cancellationToken);
            if (!lease.IsCurrent())
            {
                return null;
            }
            var (md5, sha1, sha256) = Hashes(stream, cancellationToken);
            if (!lease.IsCurrent())
            {
                return null;
            }
            return new FileSignatureReport(
                lease.FullPath,
                verdict.State,
                verdict.Signer,
                verdict.Anchor,
                verdict.Revocation,
                md5,
                sha1,
                sha256);
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            return null;
        }
    }

    private static (string Md5, string Sha1, string Sha256) Hashes(
        FileStream stream,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // MD5 and SHA-1 are weak for security decisions and are used here only as file identifiers:
        // they are the hashes VirusTotal and other tools key on, so a signature window must show them.
#pragma warning disable CA5350, CA5351
        var md5 = Convert.ToHexString(MD5.HashData(stream));
        cancellationToken.ThrowIfCancellationRequested();
        stream.Position = 0;
        var sha1 = Convert.ToHexString(SHA1.HashData(stream));
#pragma warning restore CA5350, CA5351
        cancellationToken.ThrowIfCancellationRequested();
        stream.Position = 0;
        var sha256 = Convert.ToHexString(SHA256.HashData(stream));
        return (md5, sha1, sha256);
    }
}
