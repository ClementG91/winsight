namespace WinSight.Core;

/// <summary>
/// Verifies the Authenticode standing of files. An interface so the fast native
/// implementation (WTGetSignatureInfo) can replace the current one without touching
/// callers, and so tools can be tested with a stub.
/// </summary>
public interface ISignatureVerifier
{
    /// <summary>Verifies a single file.</summary>
    SignatureVerdict Verify(string path);

    /// <summary>
    /// Verifies many files at once. Implementations SHOULD batch (the point of the
    /// method) — a scan resolves dozens of images and per-file process spawns would
    /// be slow. Returns a verdict per input path (case-insensitive keys).
    /// </summary>
    IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(IReadOnlyCollection<string> paths);
}
