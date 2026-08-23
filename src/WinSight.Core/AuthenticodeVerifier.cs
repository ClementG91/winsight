namespace WinSight.Core;

/// <summary>
/// Compatibility name for WinSight's Authenticode verifier. Verification is entirely native:
/// embedded signatures use WinVerifyTrust and catalog signatures use the local catalog APIs, with
/// cache-only trust evaluation. It never spawns PowerShell and never initiates network retrieval.
/// </summary>
public sealed class AuthenticodeVerifier : ISignatureVerifier
{
    private readonly NativeSignatureVerifier _native = new();

    public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default) =>
        _native.Verify(path, cancellationToken);

    public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
        IReadOnlyCollection<string> paths,
        CancellationToken cancellationToken = default) =>
        _native.VerifyMany(paths, cancellationToken);

    /// <summary>
    /// Maps the statuses emitted by historical PowerShell-backed releases. Retained as a public
    /// compatibility helper for callers that persist or import those status strings.
    /// </summary>
    public static SignatureVerdict MapStatus(string? status, string? signer) => status switch
    {
        "Valid" => new SignatureVerdict(SignatureState.SignedTrusted, signer),
        "NotSigned" => SignatureVerdict.Unsigned,
        "HashMismatch" or "NotTrusted" =>
            new SignatureVerdict(SignatureState.SignedUntrusted, signer),
        "UnknownError" => string.IsNullOrWhiteSpace(signer)
            ? SignatureVerdict.Unknown
            : new SignatureVerdict(SignatureState.SignedUntrusted, signer),
        _ => SignatureVerdict.Unknown,
    };
}
