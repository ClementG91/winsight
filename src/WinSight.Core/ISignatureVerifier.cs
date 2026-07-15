namespace WinSight.Core;

/// <summary>
/// Verifies the Authenticode standing of files. An interface so the fast native
/// implementation (WTGetSignatureInfo) can replace the current one without touching
/// callers, and so tools can be tested with a stub.
/// </summary>
public interface ISignatureVerifier
{
    /// <summary>Verifies a single file.</summary>
    SignatureVerdict Verify(string path, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies many files at once. Implementations SHOULD batch (the point of the
    /// method), a scan resolves dozens of images and per-file process spawns would
    /// be slow. Returns a verdict per input path (case-insensitive keys). The token lets
    /// a caller abort a slow batch (e.g. a spawned child process) mid-scan; these are
    /// synchronous methods, so cancellation is observed cooperatively at batch boundaries
    /// and by killing any child process.
    /// </summary>
    IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
        IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default);
}
