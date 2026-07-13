namespace WinSight.Core;

/// <summary>
/// The Authenticode standing of a file on disk. WinSight uses this everywhere it
/// shows "who signed this" — a persistence entry, a process, a network owner.
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
    /// the standing is genuinely undetermined — NOT the same as "unsigned". A tool that
    /// wants to earn trust must not cry wolf on files it simply failed to check, so
    /// Unknown is never treated as a flag-worthy signal.
    /// </summary>
    Unknown,
}

/// <summary>
/// The signature verdict for a file: its state plus the signer subject when signed.
/// </summary>
/// <param name="State">Coarse trust standing.</param>
/// <param name="Signer">Signer certificate subject, or null when unsigned/missing.</param>
public readonly record struct SignatureVerdict(SignatureState State, string? Signer)
{
    public static readonly SignatureVerdict Missing = new(SignatureState.Missing, null);
    public static readonly SignatureVerdict Unsigned = new(SignatureState.Unsigned, null);
    public static readonly SignatureVerdict Unknown = new(SignatureState.Unknown, null);

    /// <summary>True when the file carries any embedded signature (trusted or not).</summary>
    public bool IsSigned => State is SignatureState.SignedTrusted or SignatureState.SignedUntrusted;
}
