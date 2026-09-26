using System.Runtime.InteropServices;

using Microsoft.Win32.SafeHandles;

namespace WinSight.Core;

public static partial class AutomaticFileAccess
{
    /// <summary>
    /// Creates every missing component of a local directory without following a reparse point.
    /// Existing ordinary components are reused; an inaccessible or reparse component fails closed.
    /// </summary>
    public static bool TryEnsureDirectory(string? path)
    {
        using var lease = TryAcquireOrCreateDirectory(path);
        return lease is not null;
    }

    /// <summary>
    /// Applies a protected discretionary ACL to the exact ordinary local directory handle. The
    /// descriptor must be self-relative, as returned by .NET access-control APIs.
    /// </summary>
    public static bool TryApplyProtectedDirectoryDacl(
        string? path,
        ReadOnlySpan<byte> securityDescriptor)
    {
        if (securityDescriptor.IsEmpty || !TryNormalize(path, out var fullPath))
        {
            return false;
        }
        using var directory = TryAcquireNormalized(
            fullPath,
            FileReadAttributes | WriteDac | Synchronize,
            (uint)FileShare.ReadWrite,
            out _);
        if (directory is not { IsDirectory: true } || directory.NativeHandle is not { } handle)
        {
            return false;
        }
        var descriptor = securityDescriptor.ToArray();
        return SetKernelObjectSecurity(
            handle,
            DaclSecurityInformation | ProtectedDaclSecurityInformation,
            descriptor);
    }

    /// <summary>
    /// Creates a new ordinary local file and durably writes its content. The operation refuses to
    /// overwrite an existing entry and resolves the leaf relative to an acquired directory handle.
    /// </summary>
    public static bool TryCreateNewFile(
        string? path,
        ReadOnlySpan<byte> bytes,
        bool createParentDirectories = false)
    {
        using var lease = TryCreateNewFileLease(path, bytes, createParentDirectories);
        return lease is not null;
    }

    /// <summary>
    /// Creates and durably writes a new ordinary file, returning its still-open exact handle lease.
    /// The caller can capture identity without a path-reopen race and must dispose the result.
    /// </summary>
    public static LocalPathLease? TryCreateNewFileLease(
        string? path,
        ReadOnlySpan<byte> bytes,
        bool createParentDirectories = false)
    {
        if (!TryPrepareTarget(path, createParentDirectories, out var fullPath, out var leaf, out var parent))
        {
            return null;
        }
        using (parent)
        {
            var file = TryOpenRelative(
                parent,
                leaf,
                fullPath,
                GenericWrite | FileReadAttributes | DeleteAccess | Synchronize,
                0,
                FileCreate,
                FileNonDirectoryFile | FileSynchronousIoNonAlert | FileOpenReparsePoint | FileOpenNoRecall);
            if (file is null || file.IsDirectory)
            {
                file?.Dispose();
                return null;
            }
            if (TryWriteAndFlush(file, bytes, append: false))
            {
                return file;
            }
            file.TryDelete();
            file.Dispose();
            return null;
        }
    }

    /// <summary>
    /// Appends bytes to an ordinary local file, creating it if absent. The acquired parent and leaf
    /// are kept stable for the complete write, and reparses are refused.
    /// </summary>
    public static bool TryAppendFile(
        string? path,
        ReadOnlySpan<byte> bytes,
        bool createParentDirectories = true)
    {
        if (!TryPrepareTarget(path, createParentDirectories, out var fullPath, out var leaf, out var parent))
        {
            return false;
        }
        using (parent)
        using (var file = TryOpenOrCreateFile(parent, leaf, fullPath))
        {
            if (file is null || file.IsDirectory)
            {
                return false;
            }
            return TryWriteAndFlush(file, bytes, append: true);
        }
    }

    /// <summary>
    /// Replaces a local file atomically with durable bytes. A unique temporary file is created and
    /// renamed relative to the same acquired parent handle, so neither operation follows a reparse.
    /// </summary>
    public static bool TryWriteAtomic(
        string? path,
        ReadOnlySpan<byte> bytes,
        bool createParentDirectories = true)
    {
        if (!TryPrepareTarget(path, createParentDirectories, out var fullPath, out var leaf, out var parent))
        {
            return false;
        }
        using (parent)
        {
            var tempLeaf = $".winsight-{Guid.NewGuid():N}.tmp";
            var tempPath = Path.Combine(parent.FullPath, tempLeaf);
            using var temp = TryOpenRelative(
                parent,
                tempLeaf,
                tempPath,
                GenericWrite | FileReadAttributes | DeleteAccess | Synchronize,
                0,
                FileCreate,
                FileNonDirectoryFile | FileSynchronousIoNonAlert | FileOpenReparsePoint | FileOpenNoRecall);
            if (temp is null || temp.IsDirectory || !TryWriteAndFlush(temp, bytes, append: false))
            {
                temp?.TryDelete();
                return false;
            }
            if (TryRenameRelative(temp, parent, leaf, replaceExisting: true))
            {
                return true;
            }
            temp.TryDelete();
            return false;
        }
    }

    /// <summary>Deletes the exact ordinary local file acquired without following reparses.</summary>
    public static bool TryDeleteFile(string? path)
    {
        using var lease = TryAcquireForDelete(path);
        return lease is not null && lease.TryDelete();
    }

    private static bool TryPrepareTarget(
        string? path,
        bool createParentDirectories,
        out string fullPath,
        out string leaf,
        out LocalPathLease parent)
    {
        leaf = string.Empty;
        parent = null!;
        if (!TryNormalize(path, out fullPath))
        {
            return false;
        }
        leaf = Path.GetFileName(fullPath);
        var parentPath = Path.GetDirectoryName(fullPath);
        if (!IsSafeRelativeName(leaf) || string.IsNullOrEmpty(parentPath))
        {
            return false;
        }
        var acquiredParent = createParentDirectories
            ? TryAcquireOrCreateDirectory(parentPath)
            : TryAcquire(parentPath);
        if (acquiredParent is { IsDirectory: true })
        {
            parent = acquiredParent;
            return true;
        }
        acquiredParent?.Dispose();
        parent = null!;
        return false;
    }

    private static LocalPathLease? TryAcquireOrCreateDirectory(string? path)
    {
        if (!TryNormalize(path, out var fullPath))
        {
            return null;
        }
        var rootPath = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(rootPath))
        {
            return null;
        }
        var current = TryAcquireNormalized(
            rootPath,
            FileTraverse | FileReadAttributes | Synchronize,
            (uint)FileShare.ReadWrite,
            out _);
        if (current is not { IsDirectory: true })
        {
            current?.Dispose();
            return null;
        }
        var relative = fullPath[rootPath.Length..];
        if (relative.Length == 0)
        {
            return current;
        }
        foreach (var component in relative.Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            if (!IsSafeRelativeName(component))
            {
                current.Dispose();
                return null;
            }
            var componentPath = Path.Combine(current.FullPath, component);
            var next = TryOpenRelative(
                current,
                component,
                componentPath,
                FileTraverse | FileReadAttributes | Synchronize,
                (uint)FileShare.ReadWrite,
                FileOpen,
                FileDirectoryFile | FileSynchronousIoNonAlert);
            next ??= TryOpenRelative(
                current,
                component,
                componentPath,
                FileTraverse | FileReadAttributes | Synchronize,
                (uint)FileShare.ReadWrite,
                FileCreate,
                FileDirectoryFile | FileSynchronousIoNonAlert);
            next ??= TryOpenRelative(
                current,
                component,
                componentPath,
                FileTraverse | FileReadAttributes | Synchronize,
                (uint)FileShare.ReadWrite,
                FileOpen,
                FileDirectoryFile | FileSynchronousIoNonAlert);
            current.Dispose();
            if (next is not { IsDirectory: true })
            {
                next?.Dispose();
                return null;
            }
            current = next;
        }
        return current;
    }

    private static LocalPathLease? TryOpenRelative(
        LocalPathLease parent,
        string relativeName,
        string fullPath,
        uint desiredAccess,
        uint shareAccess,
        uint createDisposition,
        uint createOptions)
    {
        if (!parent.IsDirectory || !IsSafeRelativeName(relativeName))
        {
            return null;
        }
        var rootHandle = parent.NativeHandle;
        if (rootHandle is null || rootHandle.IsClosed)
        {
            return null;
        }
        var addedReference = false;
        var buffer = IntPtr.Zero;
        var namePointer = IntPtr.Zero;
        try
        {
            rootHandle.DangerousAddRef(ref addedReference);
            buffer = Marshal.StringToHGlobalUni(relativeName);
            var name = new UnicodeString
            {
                Length = checked((ushort)(relativeName.Length * sizeof(char))),
                MaximumLength = checked((ushort)((relativeName.Length + 1) * sizeof(char))),
                Buffer = buffer,
            };
            namePointer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
            Marshal.StructureToPtr(name, namePointer, false);
            var attributes = new ObjectAttributes
            {
                Length = Marshal.SizeOf<ObjectAttributes>(),
                RootDirectory = rootHandle.DangerousGetHandle(),
                ObjectName = namePointer,
                Attributes = ObjCaseInsensitive | ObjDontReparse,
            };
            var status = NtCreateFile(
                out var handle,
                desiredAccess,
                ref attributes,
                out _,
                IntPtr.Zero,
                0,
                shareAccess,
                createDisposition,
                createOptions,
                IntPtr.Zero,
                0);
            if (status < 0 || handle.IsInvalid)
            {
                handle.Dispose();
                return null;
            }
            if (!GetFileInformationByHandle(handle, out var information)
                || (information.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0)
            {
                handle.Dispose();
                return null;
            }
            var isDirectory = (information.FileAttributes & (uint)FileAttributes.Directory) != 0;
            var length = ((long)information.FileSizeHigh << 32) | information.FileSizeLow;
            return new LocalPathLease(
                fullPath,
                isDirectory,
                length,
                FileTimeUtc(information.CreationTime),
                FileTimeUtc(information.LastWriteTime),
                new FileIdentity(
                    information.VolumeSerialNumber,
                    ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow),
                handle,
                desiredAccess,
                shareAccess,
                information.FileAttributes);
        }
        catch (Exception ex) when (ex is ArgumentException
                                     or OverflowException
                                     or OutOfMemoryException
                                     or ObjectDisposedException)
        {
            return null;
        }
        finally
        {
            if (namePointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(namePointer);
            }
            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }
            if (addedReference)
            {
                rootHandle.DangerousRelease();
            }
        }
    }

    private static bool TryWriteAndFlush(LocalPathLease lease, ReadOnlySpan<byte> bytes, bool append)
    {
        var handle = lease.NativeHandle;
        if (handle is null || handle.IsClosed)
        {
            return false;
        }
        try
        {
            var process = GetCurrentProcess();
            if (!DuplicateHandle(
                    process,
                    handle,
                    process,
                    out var duplicate,
                    0,
                    false,
                    DuplicateSameAccess))
            {
                duplicate.Dispose();
                return false;
            }
            using var stream = new FileStream(duplicate, FileAccess.Write);
            if (append)
            {
                stream.Seek(0, SeekOrigin.End);
            }
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
            return true;
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or ObjectDisposedException)
        {
            return false;
        }
    }

    private static LocalPathLease? TryOpenOrCreateFile(
        LocalPathLease parent,
        string leaf,
        string fullPath)
    {
        const uint options = FileNonDirectoryFile
                             | FileSynchronousIoNonAlert
                             | FileOpenReparsePoint
                             | FileOpenNoRecall;
        var file = TryOpenRelative(
            parent,
            leaf,
            fullPath,
            GenericWrite | FileReadAttributes | Synchronize,
            (uint)FileShare.Read,
            FileOpen,
            options);
        file ??= TryOpenRelative(
            parent,
            leaf,
            fullPath,
            GenericWrite | FileReadAttributes | Synchronize,
            (uint)FileShare.Read,
            FileCreate,
            options);
        file ??= TryOpenRelative(
            parent,
            leaf,
            fullPath,
            GenericWrite | FileReadAttributes | Synchronize,
            (uint)FileShare.Read,
            FileOpen,
            options);
        return file;
    }

    private static bool TryRenameRelative(
        LocalPathLease source,
        LocalPathLease destinationParent,
        string destinationName,
        bool replaceExisting)
    {
        if (!IsSafeRelativeName(destinationName))
        {
            return false;
        }
        var sourceHandle = source.NativeHandle;
        var parentHandle = destinationParent.NativeHandle;
        if (sourceHandle is null || sourceHandle.IsClosed
            || parentHandle is null || parentHandle.IsClosed)
        {
            return false;
        }
        var nameBytes = checked(destinationName.Length * sizeof(char));
        var rootOffset = IntPtr.Size == sizeof(long) ? 8 : 4;
        var lengthOffset = rootOffset + IntPtr.Size;
        var nameOffset = lengthOffset + sizeof(uint);
        var bufferSize = checked(nameOffset + nameBytes + sizeof(char));
        var buffer = IntPtr.Zero;
        var addedReference = false;
        try
        {
            parentHandle.DangerousAddRef(ref addedReference);
            buffer = Marshal.AllocHGlobal(bufferSize);
            Marshal.WriteInt64(buffer, 0, 0);
            Marshal.WriteIntPtr(buffer, rootOffset, parentHandle.DangerousGetHandle());
            Marshal.WriteInt32(buffer, lengthOffset, nameBytes);
            var chars = destinationName.ToCharArray();
            Marshal.Copy(chars, 0, IntPtr.Add(buffer, nameOffset), chars.Length);
            Marshal.WriteInt16(buffer, nameOffset + nameBytes, 0);
            if (replaceExisting)
            {
                Marshal.WriteInt32(
                    buffer,
                    0,
                    unchecked((int)(FileRenameReplaceIfExists
                                    | FileRenamePosixSemantics
                                    | FileRenameIgnoreReadonlyAttribute)));
                var extendedStatus = NtSetInformationFile(
                    sourceHandle,
                    out _,
                    buffer,
                    checked((uint)bufferSize),
                    FileRenameInformationEx);
                if (extendedStatus >= 0)
                {
                    return true;
                }
                Marshal.WriteInt64(buffer, 0, 0);
                Marshal.WriteByte(buffer, 0, 1);
            }
            var status = NtSetInformationFile(
                sourceHandle,
                out _,
                buffer,
                checked((uint)bufferSize),
                FileRenameInformation);
            return status >= 0;
        }
        catch (Exception ex) when (ex is ArgumentException
                                     or OverflowException
                                     or OutOfMemoryException
                                     or ObjectDisposedException)
        {
            return false;
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }
            if (addedReference)
            {
                parentHandle.DangerousRelease();
            }
        }
    }

    private static bool IsSafeRelativeName(string name) =>
        name.Length > 0
        && name is not "." and not ".."
        && name.IndexOfAny([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar, ':']) < 0;

    private const uint GenericWrite = 0x40000000;
    private const uint WriteDac = 0x00040000;
    private const uint FileTraverse = 0x00000020;
    private const uint FileCreate = 0x00000002;
    private const uint FileDirectoryFile = 0x00000001;
    private const uint FileNonDirectoryFile = 0x00000040;
    private const int FileRenameInformation = 10;
    private const int FileRenameInformationEx = 65;
    private const uint FileRenameReplaceIfExists = 0x00000001;
    private const uint FileRenamePosixSemantics = 0x00000002;
    private const uint FileRenameIgnoreReadonlyAttribute = 0x00000040;
    private const uint DaclSecurityInformation = 0x00000004;
    private const uint ProtectedDaclSecurityInformation = 0x80000000;

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtSetInformationFile(
        SafeFileHandle file,
        out IoStatusBlock ioStatusBlock,
        IntPtr fileInformation,
        uint bufferSize,
        int fileInformationClass);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetKernelObjectSecurity(
        SafeFileHandle handle,
        uint securityInformation,
        byte[] securityDescriptor);
}
