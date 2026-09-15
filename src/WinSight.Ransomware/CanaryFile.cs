using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using WinSight.Core;

namespace WinSight.Ransomware;

/// <summary>Identity recorded while the exclusively created decoy is still open.</summary>
internal sealed record CanaryFileIdentity(ulong Volume, ulong FileIdLow, ulong FileIdHigh, long CreationTime);

internal sealed record CanaryFileRecord(string Path, CanaryFileIdentity Identity)
{
    /// <summary>The planting session; a record whose session is still alive is not an orphan.</summary>
    public string? Owner { get; init; }
}

/// <summary>
/// Cleanup authorises one original, pristine file, never a pathname. The exclusive write/delete
/// sharing restriction lasts from identity/content verification through handle-based disposition.
/// A missing identity, unsupported filesystem, changed document or replacement is preserved.
/// </summary>
internal static class CanaryFile
{
    internal static CanaryFileIdentity? Identity(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var info)
            || !GetFileInformationByHandleEx(handle, 18, out var id, 24)
            || (info.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
        {
            return null;
        }
        // FILE_ID_INFO supplies the full 128-bit identity (needed on ReFS); do not fall back to
        // BY_HANDLE_FILE_INFORMATION's truncated file index on filesystems that cannot supply it.
        return new CanaryFileIdentity(id.VolumeSerialNumber, id.FileIdLow, id.FileIdHigh,
            ((long)info.CreationTimeHigh << 32) | info.CreationTimeLow);
    }

    internal static bool TryRemove(CanaryFileRecord record)
    {
        try
        {
            if (!AutomaticFileAccess.IsLocal(record.Path))
            {
                return false;
            }
            // OPEN_REPARSE_POINT rejects a final symlink instead of following its target. No
            // FILE_SHARE_WRITE/DELETE: concurrent writers and path substitutions cannot intervene
            // after this open. If a writer already exists, opening fails and we preserve the file.
            using var handle = CreateFileW(record.Path, 0x80000000 | 0x00010000,
                FileShare.Read, IntPtr.Zero, FileMode.Open, 0x00200000, IntPtr.Zero);
            if (handle.IsInvalid || Identity(handle) != record.Identity)
            {
                return false;
            }
            using var stream = new FileStream(handle, FileAccess.Read);
            var expected = CanaryDocument.For(System.IO.Path.GetExtension(record.Path));
            if (stream.Length != expected.Length)
            {
                return false;
            }
            var actual = new byte[expected.Length];
            stream.ReadExactly(actual);
            if (!actual.AsSpan().SequenceEqual(expected))
            {
                return false;
            }
            var disposition = new FileDisposition { DeleteFile = true };
            return SetFileInformationByHandle(handle, 4, ref disposition, 1);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                     or System.Security.SecurityException or ArgumentException)
        {
            return false;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        internal FileAttributes Attributes;
        internal uint CreationTimeLow;
        internal uint CreationTimeHigh;
        internal uint LastAccessTimeLow;
        internal uint LastAccessTimeHigh;
        internal uint LastWriteTimeLow;
        internal uint LastWriteTimeHigh;
        internal uint VolumeSerialNumber;
        internal uint FileSizeHigh;
        internal uint FileSizeLow;
        internal uint NumberOfLinks;
        internal uint FileIndexHigh;
        internal uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInformation
    {
        internal ulong VolumeSerialNumber;
        internal ulong FileIdLow;
        internal ulong FileIdHigh;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDisposition
    {
        [MarshalAs(UnmanagedType.U1)]
        internal bool DeleteFile;
    }

    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess,
        FileShare shareMode, IntPtr securityAttributes, FileMode creationDisposition,
        uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation info);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass,
        out FileIdInformation information, uint bufferSize);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file, int informationClass,
        ref FileDisposition information, uint bufferSize);
}
