namespace WinSight.Core;

/// <summary>The outcome of one native exclusive sidecar acquisition attempt.</summary>
public enum LocalFileLockStatus
{
    Acquired,
    Missing,
    Busy,
    UnsafePath,
    Unavailable,
}

public static partial class AutomaticFileAccess
{
    /// <summary>
    /// Holds both the parent identity and a DATA read handle with no sharing. Closing it releases
    /// the lock; the persistent sidecar is never deleted, including after a failed operation.
    /// </summary>
    public sealed class LocalFileLock : IDisposable
    {
        private readonly LocalPathLease _parent;
        private LocalPathLease? _file;
        private LocalPathLease? _bootstrap;
        private readonly List<LocalPathLease> _writeParents = [];

        internal LocalFileLock(LocalPathLease parent, LocalPathLease? file, LocalPathLease? bootstrap = null)
        {
            _parent = parent;
            _file = file;
            _bootstrap = bootstrap;
        }

        public void Dispose()
        {
            _file?.Dispose();
            _bootstrap?.Dispose();
            foreach (var lease in _writeParents)
            {
                lease.Dispose();
            }
            _parent.Dispose();
        }

        // Writer-only. Mutators traverse every ancestor, so protect that entire ordinary path
        // against an unrelated legacy reader's exclusive directory bootstrap. Use the mutator's
        // minimal access mask: directory listing is not required. No waiting with a sidecar held.
        internal bool TryProtectParentWrites(out LocalFileLockStatus status)
        {
            status = LocalFileLockStatus.Unavailable;
            var root = Path.GetPathRoot(_parent.FullPath);
            if (string.IsNullOrEmpty(root))
            {
                return false;
            }
            var current = TryAcquireNormalized(root, FileTraverse | FileReadAttributes | Synchronize,
                (uint)FileShare.ReadWrite, out var error);
            if (!KeepParent(current, error, out status))
            {
                return false;
            }
            foreach (var component in _parent.FullPath[root.Length..].Split(
                         [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                         StringSplitOptions.RemoveEmptyEntries))
            {
                var nextPath = Path.Combine(current!.FullPath, component);
                var next = TryOpenRelative(current, component, nextPath,
                    FileTraverse | FileReadAttributes | Synchronize, (uint)FileShare.ReadWrite,
                    FileOpen, FileDirectoryFile | FileSynchronousIoNonAlert | FileOpenReparsePoint,
                    out error);
                if (!KeepParent(next, error, out status))
                {
                    return false;
                }
                current = next;
            }
            if (current!.Identity != _parent.Identity || !_parent.IsCurrent()
                || _file is null || !_file.IsCurrent())
            {
                status = LocalFileLockStatus.Unavailable;
                return false;
            }
            status = LocalFileLockStatus.Acquired;
            return true;
        }

        private bool KeepParent(LocalPathLease? lease, int error, out LocalFileLockStatus status)
        {
            status = LockStatus(error);
            if (lease is { IsDirectory: true, DataIsLocal: true })
            {
                _writeParents.Add(lease);
                return true;
            }
            if (lease is not null)
            {
                status = LocalFileLockStatus.UnsafePath;
                lease.Dispose();
            }
            return false;
        }

        // Called only from the writer gateway. Read callers never reach a create disposition.
        internal bool TryInitializeSidecar(string fullPath, out LocalFileLockStatus status)
        {
            status = LocalFileLockStatus.Unavailable;
            if (_bootstrap is null)
            {
                return false;
            }
            _file = TryOpenRelative(_bootstrap, Path.GetFileName(fullPath), fullPath,
                GenericRead | FileReadAttributes | Synchronize, 0, 3,
                FileSynchronousIoNonAlert | FileOpenReparsePoint | FileOpenNoRecall, out var error);
            _bootstrap.Dispose();
            _bootstrap = null;
            status = LockStatus(error);
            if (_file is not { IsDirectory: false, DataIsLocal: true })
            {
                if (_file is not null)
                {
                    status = LocalFileLockStatus.UnsafePath;
                }
                return false;
            }
            if (!_parent.IsCurrent() || !_file.IsCurrent())
            {
                status = LocalFileLockStatus.Unavailable;
                return false;
            }
            status = LocalFileLockStatus.Acquired;
            return true;
        }
    }

    /// <summary>Writer-only: creates missing ordinary parents and the persistent lock sidecar.</summary>
    public static LocalFileLock? TryAcquireExclusiveLockFile(string? path, out LocalFileLockStatus status)
    {
        status = LocalFileLockStatus.UnsafePath;
        if (!TryNormalize(path, out var fullPath) || Path.GetDirectoryName(fullPath) is not { Length: > 0 } parentPath)
        {
            return null;
        }
        using (var parent = TryAcquireNormalized(parentPath, FileReadAttributes | Synchronize,
                   (uint)FileShare.ReadWrite, out var error))
        {
            if (parent is null && error is 2 or 3 && !TryEnsureDirectory(parentPath))
            {
                status = LocalFileLockStatus.Unavailable;
                return null;
            }
        }
        var gate = TryAcquireExistingLockFile(fullPath, out status);
        if (gate is null)
        {
            return null;
        }
        if ((status != LocalFileLockStatus.Missing || gate.TryInitializeSidecar(fullPath, out status))
            && gate.TryProtectParentWrites(out status))
        {
            return gate;
        }
        gate.Dispose();
        return null;
    }

    /// <summary>Reader-only: opens an existing sidecar; creates no files or directories.</summary>
    public static LocalFileLock? TryAcquireExistingLockFile(string? path, out LocalFileLockStatus status)
    {
        return TryAcquireCoordinatedLock(path, out status);
    }

    private static LocalFileLock? TryAcquireCoordinatedLock(string? path, out LocalFileLockStatus status)
    {
        status = LocalFileLockStatus.UnsafePath;
        if (!TryNormalize(path, out var fullPath))
        {
            return null;
        }
        var parentPath = Path.GetDirectoryName(fullPath);
        var leaf = Path.GetFileName(fullPath);
        if (string.IsNullOrEmpty(parentPath) || !IsSafeRelativeName(leaf))
        {
            return null;
        }
        // Metadata access does not participate in DATA sharing. Do not keep a traversal handle
        // from directory creation: it would conflict with the exclusive bootstrap DATA gate.
        var parent = TryAcquireNormalized(parentPath, FileReadAttributes | Synchronize,
            (uint)FileShare.ReadWrite, out var error);
        if (parent is not { IsDirectory: true })
        {
            status = parent is null ? LockStatus(error) : LocalFileLockStatus.UnsafePath;
            parent?.Dispose();
            return null;
        }
        var existing = TryOpenRelative(parent, leaf, fullPath, GenericRead | FileReadAttributes | Synchronize,
            0, FileOpen, FileSynchronousIoNonAlert | FileOpenReparsePoint | FileOpenNoRecall, out error);
        if (existing is not null || error is not (2 or 3))
        {
            // Established locks need no directory DATA gate; directory watchers must not affect them.
            return CompleteLock(parent, existing, error, out status);
        }
        // Bootstrap participants take directory -> sidecar in that order. A legacy reader retains the
        // directory gate until its snapshot is complete; a writer therefore waits before creating
        // the first sidecar. With an existing sidecar, release the directory gate BEFORE mutations.
        var bootstrap = TryAcquireNormalized(parentPath, GenericRead | FileReadAttributes | Synchronize,
            0, out error);
        if (bootstrap is null)
        {
            parent.Dispose();
            status = LockStatus(error);
            return null;
        }
        if (!parent.IsCurrent() || bootstrap.Identity != parent.Identity)
        {
            bootstrap.Dispose();
            parent.Dispose();
            return null;
        }
        var file = TryOpenRelative(bootstrap, leaf, fullPath, GenericRead | FileReadAttributes | Synchronize,
            0, FileOpen, FileSynchronousIoNonAlert | FileOpenReparsePoint | FileOpenNoRecall, out error);
        if (file is null && error is 2 or 3)
        {
            status = LocalFileLockStatus.Missing;
            return new LocalFileLock(parent, null, bootstrap);
        }
        bootstrap.Dispose();
        return CompleteLock(parent, file, error, out status);
    }

    /// <summary>
    /// Read-only bootstrap for legacy state: DATA access and Read sharing deny writes and deletes
    /// while the snapshot and its coverage are read. The caller must verify sidecar absence too.
    /// </summary>
    public static LocalPathLease? TryAcquireStableRead(string? path, out bool missing)
    {
        missing = false;
        if (!TryNormalize(path, out var fullPath))
        {
            return null;
        }
        var lease = TryAcquireNormalized(fullPath, GenericRead | FileReadAttributes | Synchronize,
            (uint)FileShare.Read, out var error);
        missing = lease is null && error is 2 or 3;
        return lease;
    }

    private static LocalFileLock? CompleteLock(LocalPathLease parent, LocalPathLease? file,
        int error, out LocalFileLockStatus status)
    {
        status = LockStatus(error);
        if (file is { IsDirectory: false, DataIsLocal: true } && parent.IsCurrent() && file.IsCurrent())
        {
            status = LocalFileLockStatus.Acquired;
            return new LocalFileLock(parent, file);
        }
        if (file is not null)
        {
            status = LocalFileLockStatus.UnsafePath;
        }
        file?.Dispose();
        parent.Dispose();
        return null;
    }

    private static LocalFileLockStatus LockStatus(int error) => error switch
    {
        2 or 3 => LocalFileLockStatus.Missing,
        32 or 33 => LocalFileLockStatus.Busy,
        267 or 1920 or 4390 or 4392 or 4393 => LocalFileLockStatus.UnsafePath,
        _ => LocalFileLockStatus.Unavailable,
    };
}
