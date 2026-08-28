namespace WinSight.Certificates;

/// <summary>
/// A certificate found in a trusted-root store, reduced to the fields that matter for
/// a trust-hygiene review. A rogue root here means silent TLS interception (Superfish
/// / eDellRoot-class), so the audit flags the tell-tale signals.
/// </summary>
/// <param name="Store">Store it was read from (e.g. "LocalMachine\\Root").</param>
/// <param name="Subject">Certificate subject.</param>
/// <param name="Issuer">Certificate issuer.</param>
/// <param name="Thumbprint">SHA-1 thumbprint.</param>
/// <param name="SignatureAlgorithm">Signature algorithm friendly name.</param>
/// <param name="KeyBits">Public key size in bits (0 when unknown).</param>
/// <param name="IsRsa">Whether the public key is RSA (weak-key check only applies to RSA).</param>
/// <param name="HasPrivateKey">Whether the machine holds the root's private key.</param>
/// <param name="IsSelfSigned">Whether the certificate is self-signed (Subject == Issuer).</param>
/// <param name="NotAfter">Expiry.</param>
/// <param name="IsUserInstalled">
/// Trusted for this user only, i.e. present in <c>CurrentUser\Root</c> and absent from
/// <c>LocalMachine\Root</c>. Windows' own root program updates land machine-wide, so a root that
/// exists only in the user view is one somebody put there - which needs no elevation at all.
/// </param>
public sealed record TrustedCertificate(
    string Store,
    string Subject,
    string Issuer,
    string Thumbprint,
    string SignatureAlgorithm,
    int KeyBits,
    bool IsRsa,
    bool HasPrivateKey,
    bool IsSelfSigned,
    DateTime NotAfter,
    bool IsUserInstalled = false)
{
    /// <summary>
    /// Concrete reasons this trusted root warrants review, empty for a clean root.
    /// </summary>
    public IReadOnlyList<string> Risks
    {
        get
        {
            var risks = new List<string>();
            if (IsUserInstalled)
            {
                // The signal the three checks below all miss. This type's own summary claims to
                // catch Superfish / eDellRoot-class rogue roots, and a freshly generated
                // RSA-4096 / SHA-256 self-signed root has no private key on the machine, no weak
                // signature and no undersized key - so it passed every existing test while doing
                // exactly what those incidents did. It is also the cheapest step of the whole
                // attack: CurrentUser\Root is writable by any account, with no prompt, and one
                // import makes every certificate issued beneath it verify as trusted - to Windows,
                // to browsers, and to WinSight's own Authenticode verdicts.
                //
                // Deliberately worded as a fact rather than an accusation: enterprise deployment
                // and local development tools legitimately install roots this way.
                risks.Add("trusted for this user only - a root an unprivileged program can install");
            }
            if (HasPrivateKey)
            {
                // A legitimate public root never ships its private key to your machine.
                // Its presence means arbitrary trusted certificates can be minted locally.
                risks.Add("trusted root holds a private key (can mint trusted certs)");
            }
            // A weak signature only matters when someone else vouched for the cert. A
            // root is SELF-signed, so its own SHA-1 signature is not a trust input, the
            // OS trusts it by identity, not by verifying that signature. Nearly every
            // long-established public root (DigiCert, Baltimore, Comodo…) is SHA-1
            // self-signed, so flagging those is pure noise. A weak signature on a
            // NON-self-signed cert sitting in the root store, however, is genuinely odd.
            if (!IsSelfSigned && IsWeakSignature(SignatureAlgorithm))
            {
                risks.Add($"weak signature algorithm ({SignatureAlgorithm}) on a non-self-signed root-store cert");
            }
            if (IsRsa && KeyBits is > 0 and < 2048)
            {
                risks.Add($"undersized RSA key ({KeyBits}-bit)");
            }
            return risks;
        }
    }

    /// <summary>True when this trusted root shows at least one review-worthy signal.</summary>
    public bool Notable => Risks.Count > 0;

    /// <summary>SHA-1 / MD5 signatures are broken for collision resistance.</summary>
    public static bool IsWeakSignature(string algorithm) =>
        algorithm.Contains("md5", StringComparison.OrdinalIgnoreCase) ||
        algorithm.Contains("sha1", StringComparison.OrdinalIgnoreCase) ||
        algorithm.Contains("md2", StringComparison.OrdinalIgnoreCase);
}
