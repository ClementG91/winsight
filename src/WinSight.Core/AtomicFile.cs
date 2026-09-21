namespace WinSight.Core;

/// <summary>
/// Writes a file so a reader never sees a half-written state: the bytes go to a unique temporary
/// file that is flushed to disk and then moved over the target. An interrupted write leaves either
/// the previous file or nothing, never a truncated file that would read back as malformed.
/// </summary>
/// <remarks>
/// This is the pattern already used for the Guardian baseline, the decoy manifest and the decoy
/// seed; it is factored here so new state stores share one audited implementation. It performs no
/// network I/O and refuses a non-local target, matching the rest of the product.
/// </remarks>
public static class AtomicFile
{
    /// <summary>
    /// Replaces <paramref name="path"/> with <paramref name="bytes"/> atomically. Returns false when
    /// the path is not local or the write could not be completed; the previous file is left intact.
    /// </summary>
    public static bool TryWrite(string path, ReadOnlySpan<byte> bytes)
        => AutomaticFileAccess.TryWriteAtomic(path, bytes);

    /// <summary>Best-effort removal of a stray temporary file; failure is not fatal.</summary>
    public static void TryDelete(string path)
        => _ = AutomaticFileAccess.TryDeleteFile(path);
}
