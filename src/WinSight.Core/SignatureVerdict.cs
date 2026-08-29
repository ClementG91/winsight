namespace WinSight.Core;

/// <summary>
/// The Authenticode standing of a file on disk. WinSight uses this everywhere it
/// shows "who signed this", a persistence entry, a process, a network owner.
/// </summary>
public enum SignatureState
{
    /// <summary>The target file does not exist.</summary>
    Missing,

    /// <summary>No embedded Authenticode signature.</summary>
    Unsigned,

    /// <summary>Signed, but the certificate chain did not validate.</summary>
    SignedUntrusted,

    /// <summary>Signed and the certificate chain validated to a trusted root.</summary>
    SignedTrusted,

    /// <summary>
    /// Verification could not be completed (e.g. the catalog check could not run), so
    /// the standing is genuinely undetermined, NOT the same as "unsigned". A tool that
    /// wants to earn trust must not call the file malicious merely because verification failed.
    /// Consumers surface aggregate Unknown results as a scan-coverage finding instead.
    /// </summary>
    Unknown,
}

/// <summary>
/// Where a <see cref="SignatureState.SignedTrusted"/> verdict's trust actually came from.
/// </summary>
/// <remarks>
/// "The chain reached a trusted root" is not one fact but two, and the difference is the whole
/// attack. <c>WinVerifyTrust</c> runs the default policy, which consults <c>CurrentUser\Root</c> —
/// a store any account writes with no elevation at all. A self-signed root imported there, and a
/// leaf issued by it, made an implant read <c>SignatureValid</c> everywhere in WinSight. The state
/// alone could not express the difference, so this says which anchor the verdict rests on.
/// </remarks>
public enum SignatureTrustAnchor
{
    /// <summary>
    /// Not determined. Either the file is not trusted-signed, or the machine has no user-installed
    /// root so the question could not arise. Never an assertion that the anchor is sound.
    /// </summary>
    Unspecified,

    /// <summary>The chain terminates in a root Windows itself trusts machine-wide.</summary>
    MachineRoot,

    /// <summary>
    /// The chain terminates in a root present only for this user — one an unprivileged principal
    /// can install. The signature is real; what it is worth is a separate question.
    /// </summary>
    UserInstalledRoot,
}

/// <summary>
/// The signature verdict for a file: its state plus the signer subject when signed.
/// </summary>
/// <summary>
/// Whether the signing certificate's revocation status was actually established.
/// </summary>
/// <remarks>
/// <b>Why this is reported rather than folded into the verdict.</b> Revocation runs cache-only, so
/// nothing leaves the machine during a scan - a deliberate choice, and the right one. The
/// consequence is that on a machine with no cached CRL or OCSP response Windows reports the check as
/// undetermined, and WinSight maps that to trusted, because refusing to trust ordinary signed
/// software on every offline machine would be a false accusation.
///
/// That mapping is correct and it also throws away the one fact an operator investigating a stolen
/// certificate needs. Campaigns using stolen signing keys run for months past the revocation, and
/// "signature valid" is exactly what those binaries produce. The verdict now says which of the two
/// it is, so "valid" and "valid, and revocation was not established" stop reading identically.
/// </remarks>
public enum RevocationStanding
{
    /// <summary>Not established either way, or the question does not apply.</summary>
    Unspecified,

    /// <summary>Revocation was checked against the local cache and the certificate was not revoked.</summary>
    NotRevoked,

    /// <summary>
    /// The check could not run: nothing cached to answer from, and a scan never fetches. This is not
    /// evidence against the file - it is the absence of evidence either way.
    /// </summary>
    NotChecked,

    /// <summary>The certificate was revoked.</summary>
    Revoked,
}

/// <param name="State">Coarse trust standing.</param>
/// <param name="Signer">Signer certificate subject, or null when unsigned/missing.</param>
/// <param name="Anchor">Which trusted root a <see cref="SignatureState.SignedTrusted"/> rests on.</param>
/// <param name="Revocation">Whether revocation was actually established. See the enum for why.</param>
public readonly record struct SignatureVerdict(
    SignatureState State,
    string? Signer,
    SignatureTrustAnchor Anchor = SignatureTrustAnchor.Unspecified,
    RevocationStanding Revocation = RevocationStanding.Unspecified)
{
    public static readonly SignatureVerdict Missing = new(SignatureState.Missing, null);
    public static readonly SignatureVerdict Unsigned = new(SignatureState.Unsigned, null);
    public static readonly SignatureVerdict Unknown = new(SignatureState.Unknown, null);

    /// <summary>True when the file carries any embedded signature (trusted or not).</summary>
    public bool IsSigned => State is SignatureState.SignedTrusted or SignatureState.SignedUntrusted;

    /// <summary>
    /// True when the verdict is only as good as a root an unprivileged principal could have
    /// installed. A triage hint, not an accusation: an enterprise root legitimately looks like this.
    /// </summary>
    public bool RestsOnUserInstalledTrust =>
        State == SignatureState.SignedTrusted && Anchor == SignatureTrustAnchor.UserInstalledRoot;

    /// <summary>
    /// True when the file is trusted but its revocation status was never established.
    /// </summary>
    /// <remarks>
    /// A triage hint, not an accusation, exactly like <see cref="RestsOnUserInstalledTrust"/>: it is
    /// the ordinary state of every signed file on a machine that has not talked to a CRL
    /// distribution point. It matters when the question is whether a certificate was stolen, because
    /// that is the one case where "valid" and "valid, unverified" differ.
    /// </remarks>
    public bool TrustedWithoutRevocationCheck =>
        State == SignatureState.SignedTrusted && Revocation == RevocationStanding.NotChecked;
}
