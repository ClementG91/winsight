using System.Runtime.InteropServices;
using System.Security.Cryptography;

using Microsoft.Win32.SafeHandles;

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

    public string? ImageFileName(int pid)
    {
        using var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle.IsInvalid)
        {
            // A process WinSight cannot open is not one it can act on either; the responder will
            // capture null and refuse. The reserved pids are still caught by the protected check.
            return null;
        }
        var path = QueryImagePath(handle);
        return path is null ? null : System.IO.Path.GetFileName(path);
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
            if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath))
            {
                return null;
            }
            using var stream = new FileStream(imagePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            return Convert.ToHexString(SHA256.HashData(stream));
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
