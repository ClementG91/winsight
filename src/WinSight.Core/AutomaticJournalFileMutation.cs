namespace WinSight.Core;

public static partial class AutomaticFileAccess
{
    /// <summary>
    /// Journal-only atomic replacement with one deterministic crash staging file per destination.
    /// Callers must hold the journal's cross-session file lock for this path and all its evidence paths.
    /// An existing staging path is preserved: its name alone is not proof that this operation owns it.
    /// Set replaceExisting to false for the first publication after native confirmed absence.
    /// </summary>
    public static bool TryWriteAtomicBounded(string path, ReadOnlySpan<byte> bytes, bool replaceExisting = true)
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
                && TryRenameRelative(temp, parent, leaf, replaceExisting))
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
    /// Requires the same journal file lock as <see cref="TryWriteAtomicBounded"/>.
    /// </summary>
    public static bool TryCopyTailAtomic(string sourcePath, string destinationPath, int maxBytes, bool replaceExisting = false)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maxBytes, 0);
        using var source = replaceExisting ? TryAcquireReplaceableRead(sourcePath) : TryAcquire(sourcePath);
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
                if (source.IsCurrent() && TryRenameRelative(temp, parent, leaf, replaceExisting))
                {
                    return true;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ObjectDisposedException)
            {
                // The source remains authoritative. Only this freshly created handle is cleaned up.
            }
            temp.TryDelete();
            return false;
        }
    }

    private static LocalPathLease? CreateJournalStaging(LocalPathLease parent, string fullPath, string leaf)
    {
        var tempLeaf = leaf + ".winsight-journal.tmp";
        var tempPath = fullPath + ".winsight-journal.tmp";
        // FILE_CREATE atomically refuses any existing entry. A predictable suffix cannot prove
        // ownership: this may be another configured journal or an unrelated operator file.
        // Never acquire/delete unknown bytes, even when they look like a partial crash copy.
        return TryOpenRelative(parent, tempLeaf, tempPath,
            GenericWrite | FileReadAttributes | DeleteAccess | Synchronize, 0, FileCreate,
            FileNonDirectoryFile | FileSynchronousIoNonAlert | FileOpenReparsePoint | FileOpenNoRecall);
    }
}
