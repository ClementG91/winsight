namespace WinSight.Core;

public static partial class AutomaticFileAccess
{
    /// <summary>
    /// Journal-only atomic replacement with one deterministic crash staging file per destination.
    /// Callers must hold the journal's cross-session mutex for this path and all its evidence paths.
    /// </summary>
    public static bool TryWriteAtomicBounded(string path, ReadOnlySpan<byte> bytes)
    {
        if (!TryPrepareTarget(path, true, out var fullPath, out var leaf, out var parent))
        {
            return false;
        }
        using (parent)
        using (var temp = CreateJournalStaging(parent, fullPath, leaf))
        {
            if (temp is null)
            {
                return false;
            }
            if (TryWriteAndFlush(temp, bytes, append: false)
                && TryRenameRelative(temp, parent, leaf, replaceExisting: true))
            {
                return true;
            }
            temp.TryDelete();
            return false;
        }
    }

    /// <summary>
    /// Copies at most maxBytes from an exact local source tail with a fixed 80KiB buffer. Flushes
    /// staging before publishing create-new evidence; keeps source intact if any step fails.
    /// Requires the same journal mutex as <see cref="TryWriteAtomicBounded"/>.
    /// </summary>
    public static bool TryCopyTailAtomic(string sourcePath, string destinationPath, int maxBytes)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maxBytes, 0);
        using var source = TryAcquire(sourcePath);
        if (source is null || source.IsDirectory
            || !TryPrepareTarget(destinationPath, true, out var fullPath, out var leaf, out var parent))
        {
            return false;
        }
        using (parent)
        using (var temp = CreateJournalStaging(parent, fullPath, leaf))
        {
            if (temp?.NativeHandle is not { } handle)
            {
                return false;
            }
            try
            {
                var process = GetCurrentProcess();
                if (!DuplicateHandle(process, handle, process, out var duplicate, 0, false, DuplicateSameAccess))
                {
                    duplicate.Dispose();
                    temp.TryDelete();
                    return false;
                }
                using (var output = new FileStream(duplicate, FileAccess.Write))
                using (var input = source.OpenRead())
                {
                    input.Position = Math.Max(0, input.Length - maxBytes);
                    input.CopyTo(output, 80 * 1024);
                    output.Flush(flushToDisk: true);
                }
                if (source.IsCurrent() && TryRenameRelative(temp, parent, leaf, replaceExisting: false))
                {
                    return true;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ObjectDisposedException)
            {
                // The source remains authoritative, and the same staging name is retried next time.
            }
            temp.TryDelete();
            return false;
        }
    }

    private static LocalPathLease? CreateJournalStaging(LocalPathLease parent, string fullPath, string leaf)
    {
        var tempLeaf = leaf + ".winsight-journal.tmp";
        var tempPath = fullPath + ".winsight-journal.tmp";
        using (var stale = TryAcquireForDelete(tempPath, out var missing))
        {
            if (stale is null ? !missing : !stale.TryDelete())
            {
                return null;
            }
        }
        return TryOpenRelative(parent, tempLeaf, tempPath,
            GenericWrite | FileReadAttributes | DeleteAccess | Synchronize, 0, FileCreate,
            FileNonDirectoryFile | FileSynchronousIoNonAlert | FileOpenReparsePoint | FileOpenNoRecall);
    }
}
