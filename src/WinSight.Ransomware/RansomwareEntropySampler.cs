namespace WinSight.Ransomware;

/// <summary>
/// Decides whether a freshly written file "looks encrypted", by scoring a bounded prefix with
/// <see cref="ShannonEntropy"/>. This is the signal that catches ransomware rewriting documents in
/// bulk — but on its own high entropy is a notoriously noisy indicator, so it is gated twice.
/// </summary>
/// <remarks>
/// <b>Formats that are compressed by design are skipped entirely.</b> A .zip, .jpg, .mp4 — and
/// crucially .docx/.xlsx/.pptx, which are ZIP containers — are legitimately near-maximum entropy.
/// Scoring them would flag a user saving a photo or a Word document as ransomware, which is exactly
/// the kind of false positive that makes people uninstall a security tool. Ransomware that appends
/// its own extension (.locked, .encrypted, …) is still sampled, and in-place encryption that keeps
/// the original extension is covered by the canary instead.
///
/// <b>Reads are bounded.</b> Only <see cref="MaxSampleBytes"/> are read, with sharing flags that do
/// not block the writer, and any I/O trouble (locked, gone, denied) yields false rather than an
/// exception — a detector must never become the thing that breaks the machine.
/// </remarks>
public static class RansomwareEntropySampler
{
    /// <summary>How much of a file is read to score it. A prefix is enough and bounds the cost.</summary>
    public const int MaxSampleBytes = 4096;

    // Formats whose content is compressed or encrypted by design, so high entropy says nothing.
    private static readonly HashSet<string> CompressedByDesign = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".tgz", ".cab", ".iso", ".msi",
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".tiff",
        ".mp3", ".mp4", ".m4a", ".mkv", ".avi", ".mov", ".webm", ".flac",
        ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub",
        ".exe", ".dll", ".sys", ".apk", ".jar", ".nupkg", ".whl",
    };

    /// <summary>
    /// Pure: whether this path is worth scoring at all. False for formats that are compressed by
    /// design (see remarks) and for a blank path.
    /// </summary>
    public static bool ShouldSample(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }
        string extension;
        try
        {
            extension = Path.GetExtension(path);
        }
        catch (ArgumentException)
        {
            return false;
        }
        return !CompressedByDesign.Contains(extension);
    }

    /// <summary>
    /// Best-effort: reads a bounded prefix of <paramref name="path"/> and reports whether it looks
    /// encrypted. Returns false for a format compressed by design, and for any I/O trouble.
    /// </summary>
    public static bool LooksEncrypted(string? path)
    {
        if (!ShouldSample(path))
        {
            return false;
        }

        try
        {
            // Never follow a reparse point (symlink/junction), and never try to read a directory. A
            // file dropped into a watched folder can be a link to anywhere — a device, a slow network
            // share — and reading it would block this thread-pool thread. Anyone able to write to the
            // user's own folder could starve the monitor that way, so links are detected, not followed.
            var attributes = File.GetAttributes(path!);
            if (attributes.HasFlag(FileAttributes.ReparsePoint) || attributes.HasFlag(FileAttributes.Directory))
            {
                return false;
            }

            using var stream = new FileStream(
                path!,
                FileMode.Open,
                FileAccess.Read,
                // Do not fight the writer: share everything, including delete.
                FileShare.ReadWrite | FileShare.Delete);

            var buffer = new byte[MaxSampleBytes];
            var read = stream.ReadAtLeast(buffer, MaxSampleBytes, throwOnEndOfStream: false);
            return ShannonEntropy.LooksEncrypted(buffer.AsSpan(0, read));
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or NotSupportedException)
        {
            return false;
        }
    }
}
