using System.Runtime.InteropServices;
using System.Security.Cryptography;

using Microsoft.Win32.SafeHandles;

using WinSight.Core;

namespace WinSight.Response;

/// <summary>
/// The production <see cref="IProcessInspector"/>: opens a process with the minimum right needed to
/// read its start time and image path, so it works for the current user's own processes without
/// elevation and simply returns null for one it cannot open.
/// </summary>
/// <remarks>
/// Uses only documented Win32: <c>OpenProcess</c> with <c>PROCESS_QUERY_LIMITED_INFORMATION</c>,
/// <c>GetProcessTimes</c> for the creation time that makes a pid unique, and
/// <c>QueryFullProcessImageName</c> for the on-disk image. It reads and never modifies; hashing is
/// opt-in because reading a large image on every capture is wasteful when only revalidation needs it.
/// </remarks>
public sealed class Win32ProcessInspector : IProcessInspector
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    public ProcessIdentity? Capture(int pid, bool hashImage = false)
    {
        using var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle.IsInvalid)
        {
            return null;
        }
        if (!GetProcessTimes(handle, out var creation, out _, out _, out _))
        {
            return null;
        }
        var startTicks = ((long)creation.dwHighDateTime << 32) | (uint)creation.dwLowDateTime;
        var imagePath = QueryImagePath(handle) ?? string.Empty;
        var hash = hashImage ? TryHash(imagePath) : null;
        return new ProcessIdentity(pid, startTicks, imagePath, hash);
    }

    /// <summary>
    /// The image basename for display/diagnostics. It is deliberately not part of
    /// <see cref="IProcessInspector"/> and must never authorize a response action.
    /// </summary>
    public string? ImageFileName(int pid)
    {
        using var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle.IsInvalid)
        {
            return null;
        }
        var path = QueryImagePath(handle);
        return path is null ? null : Path.GetFileName(path);
    }

    private static string? QueryImagePath(SafeProcessHandle handle)
    {
        var buffer = new char[1024];
        var capacity = buffer.Length;
        return QueryFullProcessImageName(handle, 0, buffer, ref capacity) && capacity > 0
            ? new string(buffer, 0, capacity)
            : null;
    }

    private static string? TryHash(string imagePath)
    {
        try
        {
            if (string.IsNullOrEmpty(imagePath))
            {
                return null;
            }
            using var lease = AutomaticFileAccess.TryAcquire(imagePath);
            if (lease is null || lease.IsDirectory)
            {
                return null;
            }
            using var stream = lease.OpenRead(FileOptions.SequentialScan);
            var hash = Convert.ToHexString(SHA256.HashData(stream));
            return lease.IsCurrent() ? hash : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            return null;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public int dwLowDateTime;
        public int dwHighDateTime;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(
        SafeProcessHandle process, out FileTime creation, out FileTime exit, out FileTime kernel, out FileTime user);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        SafeProcessHandle process, uint flags, [Out] char[] exeName, ref int size);
}
