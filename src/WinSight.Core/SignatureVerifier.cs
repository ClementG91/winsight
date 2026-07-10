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
/// EKU=code-signing, or revocation. A tampered-but-signed binary can therefore read
/// as SignedTrusted here. WinVerifyTrust (via CsWin32) replaces this before any
/// blocking decision relies on it. Good enough for the read-only scanner's
/// signed/unsigned triage; not a trust boundary yet.
/// </summary>
public sealed class SignatureVerifier
{
    private readonly bool _checkRevocation;

    /// <param name="checkRevocation">
    /// When true the chain build performs online revocation checks (slower). The
    /// scanner defaults to false to stay fast and offline-friendly.
    /// </param>
    public SignatureVerifier(bool checkRevocation = false) => _checkRevocation = checkRevocation;

    public SignatureVerdict Verify(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return SignatureVerdict.Missing;
        }

        X509Certificate2 signer;
        try
        {
            // Throws CryptographicException when the file carries no signature.
            using var embedded = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            signer = embedded;

            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode =
                _checkRevocation ? X509RevocationMode.Online : X509RevocationMode.NoCheck;
            var trusted = chain.Build(signer);

            return new SignatureVerdict(
                trusted ? SignatureState.SignedTrusted : SignatureState.SignedUntrusted,
                signer.Subject);
        }
        catch (CryptographicException)
        {
            return SignatureVerdict.Unsigned;
        }
    }
}
