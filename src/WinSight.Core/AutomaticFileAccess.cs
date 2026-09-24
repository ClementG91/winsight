using System.ComponentModel;
using System.Runtime.InteropServices;

using Microsoft.Win32.SafeHandles;

namespace WinSight.Core;

/// <summary>
/// Acquires automatically discovered files without following a path into a network location.
/// </summary>
/// <remarks>
/// Registry values, service command lines and environment variables are attacker-controlled
/// evidence. Calling <c>File.Exists</c> on a UNC path is not a harmless predicate: Windows can
/// reach the server and authenticate the current account or machine. A drive-letter check alone is
/// insufficient because any component below that drive can be a junction or symbolic link.
///
/// <see cref="TryAcquire"/> uses the native <c>OBJ_DONT_REPARSE</c> object attribute, which makes the
/// name lookup fail if <i>any</i> component is a reparse point, plus <c>FILE_OPEN_REPARSE_POINT</c> for
/// the leaf. This is one atomic name parse: no component is followed and there is no check/open gap.
/// Reads are reopened from the acquired handle rather than from the path. The lease also records the
/// volume/file identity because modern Windows rename semantics may replace a directory entry while
/// an old handle remains valid; path-based consumers must call <see cref="LocalPathLease.IsCurrent"/>
/// before accepting their result.
/// </remarks>
public static partial class AutomaticFileAccess
{
    /// <summary>An existing ordinary local file or directory acquired without following reparses.</summary>
    public sealed class LocalPathLease : IDisposable
    {
        private SafeFileHandle? _handle;
        private readonly FileIdentity _identity;
        private readonly uint _desiredAccess;
        private readonly uint _shareAccess;
        private readonly uint _attributes;

        internal LocalPathLease(
            string fullPath,
            bool isDirectory,
            long length,
            DateTime creationTimeUtc,
            DateTime lastWriteTimeUtc,
            FileIdentity identity,
            SafeFileHandle handle,
            uint desiredAccess,
            uint shareAccess,
            uint attributes = 0)
        {
            _attributes = attributes;
            FullPath = fullPath;
            IsDirectory = isDirectory;
            Length = length;
            CreationTimeUtc = creationTimeUtc;
            LastWriteTimeUtc = lastWriteTimeUtc;
            _identity = identity;
            _handle = handle;
            _desiredAccess = desiredAccess;
            _shareAccess = shareAccess;
        }

        public string FullPath { get; }

        public bool IsDirectory { get; }

        public long Length { get; }

        internal DateTime CreationTimeUtc { get; }

        internal DateTime LastWriteTimeUtc { get; }

        internal uint VolumeSerialNumber => _identity.VolumeSerialNumber;

        internal ulong FileIndex => _identity.FileIndex;

        internal SafeFileHandle? NativeHandle => _handle;

        /// <summary>
        /// Which file this lease holds, so a later observation of the same path can prove it reached
        /// the same object rather than whatever the path names by then.
        /// </summary>
        public FileIdentity Identity => _identity;

        /// <summary>
        /// Reads the filesystem's full identifier from this exact handle. Returns false on a
        /// filesystem that does not expose <c>FILE_ID_INFO</c>; no truncated identity is invented.
        /// </summary>
        public bool TryGetExtendedIdentity(
            out ulong volumeSerialNumber,
            out ulong fileIdLow,
            out ulong fileIdHigh,
            out long creationTimeFileTimeUtc)
        {
            volumeSerialNumber = 0;
            fileIdLow = 0;
            fileIdHigh = 0;
            creationTimeFileTimeUtc = 0;
            var original = _handle;
            ObjectDisposedException.ThrowIf(original is null || original.IsClosed, this);
            if (IsDirectory
                || !GetFileInformationByHandleEx(
                    original,
                    FileIdInfo,
                    out var identity,
                    Marshal.SizeOf<FileIdInformation>()))
            {
                return false;
            }
            volumeSerialNumber = identity.VolumeSerialNumber;
            fileIdLow = identity.FileIdLow;
            fileIdHigh = identity.FileIdHigh;
            creationTimeFileTimeUtc = CreationTimeUtc.ToFileTimeUtc();
            return true;
        }

        /// <summary>
        /// False for a file whose data lives elsewhere: a cloud-only OneDrive file, or an offline one.
        /// </summary>
        /// <remarks>
        /// Reading such a file asks its provider to fetch it. Measured in the VM (gate 17), a read of a
        /// cloud-only Cloud Files placeholder sent two download requests and blocked for two minutes,
        /// even through an open that forbade recall. An automatic read never downloads (WS-40), so
        /// <see cref="OpenRead"/> refuses such a file before any open is attempted.
        /// </remarks>
        public bool DataIsLocal => (_attributes & (FileAttributeOffline | FileAttributeRecallOnOpen | FileAttributeRecallOnDataAccess)) == 0;

        /// <summary>Opens this acquired object for data reads without resolving its path again.</summary>
        public FileStream OpenRead(FileOptions options = FileOptions.SequentialScan)
            => Reopen(GenericRead, FileAccess.Read, options);

        private FileStream Reopen(uint desiredAccess, FileAccess managedAccess, FileOptions options)
        {
            var original = _handle;
            ObjectDisposedException.ThrowIf(original is null || original.IsClosed, this);
            if (IsDirectory)
            {
                throw new IOException("The acquired local path is a directory, not a file.");
            }
            if (!DataIsLocal)
            {
                throw new IOException(
                    "The file's data is not on this machine (a cloud-only or offline file); an automatic read does not download it.");
            }
            if ((_desiredAccess & GenericRead) != 0)
            {
                var process = GetCurrentProcess();
                if (!DuplicateHandle(
                        process,
                        original,
                        process,
                        out var duplicate,
                        0,
                        false,
                        DuplicateSameAccess))
                {
                    var duplicateError = Marshal.GetLastPInvokeError();
                    duplicate.Dispose();
                    throw new IOException(
                        "The acquired local file handle could not be duplicated for reading.",
                        new Win32Exception(duplicateError));
                }
                return new FileStream(duplicate, managedAccess);
            }
            var reopened = ReopenRelative(original, desiredAccess | Synchronize, _shareAccess, options, out var status);
            if (reopened is null)
            {
                throw new IOException(
                    "The acquired local file could not be reopened for reading.",
                    new Win32Exception(unchecked((int)RtlNtStatusToDosError(status))));
            }
            return new FileStream(reopened, managedAccess);
        }

        /// <summary>
        /// A new open of the very object <paramref name="original"/> refers to (an empty name relative
        /// to its handle, which is what <c>ReOpenFile</c> does inside), with recall forbidden.
        /// </summary>
        /// <remarks>
        /// The acquiring open forbade recall, but a reopen is a new open with only its own options.
        /// <c>ReOpenFile</c> without <c>FILE_FLAG_OPEN_NO_RECALL</c> let a read of a cloud-only
        /// OneDrive file ask its provider to download it - measured in the VM (gate 17): two download
        /// requests, and the read blocked for two minutes - and <c>ReOpenFile</c> rejects that flag
        /// with ERROR_INVALID_PARAMETER. An automatic read never downloads: a file whose data is not
        /// on this machine is unreadable, not fetched (WS-40).
        /// </remarks>
        private static SafeFileHandle? ReopenRelative(
            SafeFileHandle original, uint desiredAccess, uint shareAccess, FileOptions options, out int status)
        {
            var createOptions = FileSynchronousIoNonAlert | FileNonDirectoryFile | FileOpenReparsePoint | FileOpenNoRecall;
            if ((options & FileOptions.SequentialScan) != 0)
            {
                createOptions |= FileSequentialOnly;
            }
            if ((options & FileOptions.RandomAccess) != 0)
            {
                createOptions |= FileRandomAccess;
            }
            var addedReference = false;
            var namePointer = IntPtr.Zero;
            try
            {
                original.DangerousAddRef(ref addedReference);
                namePointer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
                Marshal.StructureToPtr(new UnicodeString { Length = 0, MaximumLength = 0, Buffer = IntPtr.Zero }, namePointer, false);
                var attributes = new ObjectAttributes
                {
                    Length = Marshal.SizeOf<ObjectAttributes>(),
                    RootDirectory = original.DangerousGetHandle(),
                    ObjectName = namePointer,
                    Attributes = ObjCaseInsensitive,
                };
                status = NtCreateFile(
                    out var handle, desiredAccess, ref attributes, out _, IntPtr.Zero, 0, shareAccess,
                    FileOpen, createOptions, IntPtr.Zero, 0);
                if (status < 0 || handle.IsInvalid)
                {
                    handle.Dispose();
                    return null;
                }
                return handle;
            }
            finally
            {
                if (namePointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(namePointer);
                }
                if (addedReference)
                {
                    original.DangerousRelease();
                }
            }
        }

        /// <summary>Whether the path still names this exact volume/file identity.</summary>
        public bool IsCurrent()
        {
            using var current = TryAcquire(FullPath);
            return current is not null && current._identity == _identity;
        }

        /// <summary>
        /// Marks this exact acquired file for deletion. The lease must have been returned by
        /// <see cref="TryAcquireForDelete"/>; the path is never reopened.
        /// </summary>
        public bool TryDelete()
        {
            var original = _handle;
            ObjectDisposedException.ThrowIf(original is null || original.IsClosed, this);
            if (IsDirectory)
            {
                return false;
            }
            var disposition = new FileDispositionInfoExData
            {
                Flags = FileDispositionDelete | FileDispositionIgnoreReadonlyAttribute,
            };
            return SetFileInformationByHandle(
                original,
                FileDispositionInfoEx,
                ref disposition,
                Marshal.SizeOf<FileDispositionInfoExData>());
        }

        /// <summary>
        /// Renames this exact acquired file into another ordinary local directory. The destination
        /// leaf is resolved relative to an acquired parent handle and is never opened or followed.
        /// </summary>
        public bool TryRename(string? destinationPath, bool replaceExisting = false)
        {
            var original = _handle;
            ObjectDisposedException.ThrowIf(original is null || original.IsClosed, this);
            if (IsDirectory
                || !TryNormalize(destinationPath, out var fullPath)
                || !string.Equals(
                    Path.GetDirectoryName(FullPath),
                    Path.GetDirectoryName(fullPath),
                    StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            var leaf = Path.GetFileName(fullPath);
            using var parent = TryAcquireParent(fullPath);
            return parent is { IsDirectory: true }
                   && TryRenameRelative(this, parent, leaf, replaceExisting);
        }

        public void Dispose() => Interlocked.Exchange(ref _handle, null)?.Dispose();
    }

    /// <summary>
    /// Conservative preflight classification. Existing reparse and inaccessible paths are refused.
    /// Missing local paths remain local candidates without any network name being resolved.
    /// </summary>
    public static bool IsLocal(string? path)
    {
        if (!TryNormalize(path, out var fullPath))
        {
            return false;
        }
        using var lease = TryAcquireNormalized(
            fullPath,
            FileReadAttributes | Synchronize,
            (uint)FileShare.Read,
            out var error);
        return lease is not null || error is ErrorFileNotFound or ErrorPathNotFound;
    }

    /// <summary>
    /// Atomically acquires an existing local path without following any reparse point. Returns null
    /// for missing, remote, device, reparse or inaccessible paths.
    /// </summary>
    public static LocalPathLease? TryAcquire(string? path)
    {
        if (!TryNormalize(path, out var fullPath))
        {
            return null;
        }
        return TryAcquireNormalized(
            fullPath,
            FileReadAttributes | Synchronize,
            (uint)FileShare.Read,
            out _);
    }

    /// <summary>
    /// Acquires an existing local file without following reparses while allowing another process to
    /// keep writing, reading, renaming or deleting it. Intended only for bounded observation of a
    /// live file; unlike <see cref="TryAcquire"/>, it does not claim path stability.
    /// </summary>
    public static LocalPathLease? TryAcquireSharedRead(string? path)
    {
        if (!TryNormalize(path, out var fullPath))
        {
            return null;
        }
        return TryAcquireNormalized(
            fullPath,
            FileReadAttributes | Synchronize,
            (uint)(FileShare.ReadWrite | FileShare.Delete),
            out _);
    }

    /// <summary>
    /// Acquires an existing local file for reading while allowing atomic replacement but not
    /// in-place writers. Callers must use <see cref="LocalPathLease.IsCurrent"/> after consuming it.
    /// </summary>
    public static LocalPathLease? TryAcquireReplaceableRead(string? path)
    {
        if (!TryNormalize(path, out var fullPath))
        {
            return null;
        }
        return TryAcquireNormalized(
            fullPath,
            FileReadAttributes | Synchronize,
            (uint)(FileShare.Read | FileShare.Delete),
            out _);
    }

    /// <summary>
    /// Acquires an existing ordinary local file for read-and-delete without following reparses.
    /// Content validation and deletion can therefore operate on the same object handle.
    /// </summary>
    public static LocalPathLease? TryAcquireForDelete(string? path)
    {
        if (!TryNormalize(path, out var fullPath))
        {
            return null;
        }
        var lease = TryAcquireNormalized(
            fullPath,
            GenericRead | DeleteAccess | Synchronize,
            (uint)FileShare.Read,
            out _);
        if (lease is null || !lease.IsDirectory)
        {
            return lease;
        }
        lease.Dispose();
        return null;
    }

    /// <summary>Acquires the existing parent of a target that may not exist yet.</summary>
    public static LocalPathLease? TryAcquireParent(string? path)
    {
        if (!TryNormalize(path, out var fullPath))
        {
            return null;
        }
        var parent = Path.GetDirectoryName(fullPath);
        var lease = TryAcquire(parent);
        if (lease is null || lease.IsDirectory)
        {
            return lease;
        }
        lease.Dispose();
        return null;
    }

    /// <summary>True only for an existing ordinary local file observed without following reparses.</summary>
    public static bool FileExists(string? path)
    {
        using var lease = TryAcquire(path);
        return lease is { IsDirectory: false };
    }

    /// <summary>True only for an existing ordinary local directory observed without following reparses.</summary>
    public static bool DirectoryExists(string? path)
    {
        using var lease = TryAcquire(path);
        return lease is { IsDirectory: true };
    }

    /// <summary>
    /// Reads the self-relative security descriptor of an exact local directory handle: owner,
    /// group, DACL and mandatory label. A path replacement during the read is rejected.
    /// </summary>
    /// <remarks>
    /// The label is part of who may write: a directory labelled above Medium refuses a standard
    /// user's writes whatever its DACL grants. Reading it needs no more than READ_CONTROL.
    /// </remarks>
    public static byte[]? TryReadDirectorySecurityDescriptor(string? path)
    {
        if (!TryNormalize(path, out var fullPath))
        {
            return null;
        }
        using var lease = TryAcquireNormalized(
            fullPath,
            ReadControl | FileReadAttributes | Synchronize,
            (uint)(FileShare.ReadWrite | FileShare.Delete),
            out _);
        if (lease is not { IsDirectory: true } || lease.NativeHandle is not { } handle)
        {
            return null;
        }
        _ = GetKernelObjectSecurity(
            handle,
            DirectorySecurityInformation,
            null,
            0,
            out var required);
        if (required is <= 0 or > MaximumSecurityDescriptorBytes)
        {
            return null;
        }
        var descriptor = new byte[required];
        return GetKernelObjectSecurity(
                   handle,
                   DirectorySecurityInformation,
                   descriptor,
                   descriptor.Length,
                   out _)
               && lease.IsCurrent()
            ? descriptor
            : null;
    }

    private static LocalPathLease? TryAcquireNormalized(
        string fullPath,
        uint desiredAccess,
        uint shareAccess,
        out int error)
    {
        error = 0;
        var nativePath = @"\??\" + fullPath;
        var buffer = IntPtr.Zero;
        var namePointer = IntPtr.Zero;
        try
        {
            buffer = Marshal.StringToHGlobalUni(nativePath);
            var name = new UnicodeString
            {
                Length = checked((ushort)(nativePath.Length * sizeof(char))),
                MaximumLength = checked((ushort)((nativePath.Length + 1) * sizeof(char))),
                Buffer = buffer,
            };
            namePointer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
            Marshal.StructureToPtr(name, namePointer, false);
            var attributes = new ObjectAttributes
            {
                Length = Marshal.SizeOf<ObjectAttributes>(),
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
                FileOpen,
                FileSynchronousIoNonAlert | FileOpenReparsePoint | FileOpenNoRecall,
                IntPtr.Zero,
                0);
            if (status < 0 || handle.IsInvalid)
            {
                handle.Dispose();
                error = unchecked((int)RtlNtStatusToDosError(status));
                return null;
            }
            if (!GetFileInformationByHandle(handle, out var information))
            {
                error = Marshal.GetLastPInvokeError();
                handle.Dispose();
                return null;
            }
            if ((information.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0)
            {
                // GetFileInformationByHandle succeeded, so LastError is unrelated here. Leaving
                // error at zero also prevents a stale "not found" value from accepting a reparse.
                handle.Dispose();
                return null;
            }

            var isDirectory = (information.FileAttributes & (uint)FileAttributes.Directory) != 0;
            var length = ((long)information.FileSizeHigh << 32) | information.FileSizeLow;
            var identity = new FileIdentity(
                information.VolumeSerialNumber,
                ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow);
            return new LocalPathLease(
                fullPath,
                isDirectory,
                length,
                FileTimeUtc(information.CreationTime),
                FileTimeUtc(information.LastWriteTime),
                identity,
                handle,
                desiredAccess,
                shareAccess,
                information.FileAttributes);
        }
        catch (Exception ex) when (ex is ArgumentException
                                     or OverflowException
                                     or OutOfMemoryException)
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
        }
    }

    private static DateTime FileTimeUtc(System.Runtime.InteropServices.ComTypes.FILETIME value)
    {
        var ticks = ((long)value.dwHighDateTime << 32) | (uint)value.dwLowDateTime;
        return DateTime.FromFileTimeUtc(ticks);
    }

    private static bool TryNormalize(string? path, out string fullPath)
    {
        fullPath = string.Empty;
        if (string.IsNullOrWhiteSpace(path)
            || path.StartsWith(@"\\", StringComparison.Ordinal)
            || path.StartsWith("//", StringComparison.Ordinal)
            || path.StartsWith(@"\??\", StringComparison.Ordinal)
            || path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        try
        {
            fullPath = Path.GetFullPath(path);
            var root = Path.GetPathRoot(fullPath) ?? string.Empty;
            if (root.Length < 3
                || !char.IsAsciiLetter(root[0])
                || root[1] != ':'
                || root[2] != Path.DirectorySeparatorChar)
            {
                return false;
            }
            return new DriveInfo(root).DriveType is
                DriveType.Fixed or DriveType.Removable or DriveType.CDRom or DriveType.Ram;
        }
        catch (Exception ex) when (ex is ArgumentException
                                     or IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or NotSupportedException)
        {
            return false;
        }
    }

    /// <summary>
    /// The volume and file index an acquired object had when it was opened. Two leases with equal
    /// identities opened the same file, whatever the path looked like in between.
    /// </summary>
    public readonly record struct FileIdentity(uint VolumeSerialNumber, ulong FileIndex);

    private const uint FileReadAttributes = 0x00000080;
    private const uint Synchronize = 0x00100000;
    private const uint GenericRead = 0x80000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint ReadControl = 0x00020000;
    private const uint ObjCaseInsensitive = 0x00000040;
    private const uint ObjDontReparse = 0x00001000;
    private const uint FileOpen = 0x00000001;
    private const uint FileSynchronousIoNonAlert = 0x00000020;
    private const uint FileOpenReparsePoint = 0x00200000;
    private const uint FileOpenNoRecall = 0x00400000;
    private const uint FileSequentialOnly = 0x00000004;
    private const uint FileAttributeOffline = 0x00001000;
    private const uint FileAttributeRecallOnOpen = 0x00040000;
    private const uint FileAttributeRecallOnDataAccess = 0x00400000;
    private const uint FileRandomAccess = 0x00000800;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;
    private const int FileDispositionInfoEx = 21;
    private const uint FileDispositionDelete = 0x00000001;
    private const uint FileDispositionIgnoreReadonlyAttribute = 0x00000010;
    private const uint DuplicateSameAccess = 0x00000002;
    private const int FileIdInfo = 18;
    private const int MaximumSecurityDescriptorBytes = 1024 * 1024;
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint GroupSecurityInformation = 0x00000002;
    private const uint LabelSecurityInformation = 0x00000010;

    // What a directory's descriptor is read with: owner, group, DACL and mandatory label.
    private const uint DirectorySecurityInformation =
        OwnerSecurityInformation | GroupSecurityInformation | DaclSecurityInformation | LabelSecurityInformation;

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public IntPtr Status;
        public UIntPtr Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInfoExData
    {
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInformation
    {
        public ulong VolumeSerialNumber;
        public ulong FileIdLow;
        public ulong FileIdHigh;
    }

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtCreateFile(
        out SafeFileHandle fileHandle,
        uint desiredAccess,
        ref ObjectAttributes objectAttributes,
        out IoStatusBlock ioStatusBlock,
        IntPtr allocationSize,
        uint fileAttributes,
        uint shareAccess,
        uint createDisposition,
        uint createOptions,
        IntPtr eaBuffer,
        uint eaLength);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern uint RtlNtStatusToDosError(int status);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        int fileInformationClass,
        out FileIdInformation information,
        int bufferSize);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file,
        int fileInformationClass,
        ref FileDispositionInfoExData fileInformation,
        int bufferSize);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(
        IntPtr sourceProcessHandle,
        SafeFileHandle sourceHandle,
        IntPtr targetProcessHandle,
        out SafeFileHandle targetHandle,
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint options);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetKernelObjectSecurity(
        SafeFileHandle handle,
        uint securityInformation,
        [Out] byte[]? securityDescriptor,
        int length,
        out int lengthNeeded);
}
