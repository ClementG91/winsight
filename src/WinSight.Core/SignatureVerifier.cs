using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WinSight.Core;

/// <summary>
/// Verifies a file's Authenticode signature using the managed BCL only (no P/Invoke)
/// for a dependency-light, portable-to-build MVP. It extracts the embedded signer
/// certificate and validates its chain.
///
/// KNOWN LIMITS (Phase 2 hardening, tracked): this does NOT call WinVerifyTrust, so
/// it does not check the PE hash against the signature, catalog (.cat) signatures,
/// EKU=code-signing, or revocation. Because it cannot see CATALOG signatures (which
/// cover most of Windows), a file with no EMBEDDED signature is reported as
/// <see cref="SignatureState.Unknown"/>, "could not determine", NOT
/// <see cref="SignatureState.Unsigned"/>: claiming a catalog-signed system binary is
/// unsigned would be a false alarm. It is the last-resort fallback behind the
/// catalog-aware verifiers; genuine unsigned/trusted verdicts come from those.
/// </summary>
public sealed class SignatureVerifier : ISignatureVerifier
{
    private readonly bool _checkRevocation;

    /// <param name="checkRevocation">
    /// When true the chain build performs online revocation checks (slower). The
    /// scanner defaults to false to stay fast and offline-friendly.
    /// </param>
    public SignatureVerifier(bool checkRevocation = false) => _checkRevocation = checkRevocation;

    public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(path))
        {
            return SignatureVerdict.Missing;
        }
        using var lease = AutomaticFileAccess.TryAcquire(path);
        if (lease is null)
        {
            return AutomaticFileAccess.IsLocal(path)
                ? SignatureVerdict.Missing
                : SignatureVerdict.Unknown;
        }
        if (lease.IsDirectory)
        {
            return SignatureVerdict.Unknown;
        }

        try
        {
            using var stream = lease.OpenRead(FileOptions.RandomAccess);
            using var signer = AuthenticodeCertificateReader.ReadSigner(stream);
            if (signer is null)
            {
                return SignatureVerdict.Unknown;
            }

            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode =
                _checkRevocation ? X509RevocationMode.Online : X509RevocationMode.NoCheck;
            var trusted = chain.Build(signer);
            if (!lease.IsCurrent())
            {
                return SignatureVerdict.Unknown;
            }

            return new SignatureVerdict(
                trusted ? SignatureState.SignedTrusted : SignatureState.SignedUntrusted,
                signer.Subject);
        }
        catch (Exception ex) when (ex is CryptographicException
                                     or IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            // No EMBEDDED signature, but this managed path cannot see catalog
            // signatures, so it genuinely cannot tell "unsigned" from "catalog-signed".
            // Report Unknown rather than fabricate an Unsigned false alarm.
            return SignatureVerdict.Unknown;
        }
    }

    public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
        IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default)
    {
        var results = new Dictionary<string, SignatureVerdict>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in paths)
        {
            results[path] = Verify(path, cancellationToken);
        }
        return results;
    }
}
