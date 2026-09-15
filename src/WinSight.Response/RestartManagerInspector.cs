using System.Runtime.InteropServices;

namespace WinSight.Response;

/// <summary>A process the Restart Manager reports as currently holding one of the queried files.</summary>
/// <remarks>
/// <paramref name="StartTimestampUtcTicks"/> is the raw process-creation FILETIME, the same value
/// <see cref="Win32ProcessInspector"/> reads, so the two can be compared to prove that a pid the
/// Restart Manager named has not been recycled before the identity is captured.
/// </remarks>
public sealed record RestartManagerProcess(int Pid, long StartTimestampUtcTicks, string AppName);

/// <summary>
/// Names the processes that currently hold a set of files open, behind an interface so the ransomware
/// identification logic is testable without a real locked file.
/// </summary>
public interface IFileLockInspector
{
    /// <summary>
    /// The processes the OS reports as holding any of <paramref name="files"/> open. Empty when none
    /// is found or the query cannot run; never null.
    /// </summary>
    IReadOnlyList<RestartManagerProcess> ProcessesHolding(IReadOnlyCollection<string> files);
}

/// <summary>
/// The production <see cref="IFileLockInspector"/>: the Windows Restart Manager
/// (<c>RmStartSession</c>/<c>RmRegisterResources</c>/<c>RmGetList</c>). It answers "which processes
/// have these files open" for the current user's own processes without elevation, which is exactly
/// what naming the process that just touched a decoy needs when ETW attribution is unavailable.
/// </summary>
/// <remarks>
/// The Restart Manager is a read-only query here: WinSight never asks it to restart or shut anything
/// down. The session is always ended, even on failure, so no orphaned RM session is left behind.
/// </remarks>
public sealed class RestartManagerInspector : IFileLockInspector
{
    private const int RmSessionKeyBufferLength = 33; // CCH_RM_SESSION_KEY (32) + 1 for the terminator.
    private const int ErrorSuccess = 0;
    private const int ErrorMoreData = 234;
    private const int MaxProcessInfoAttempts = 4;

    public IReadOnlyList<RestartManagerProcess> ProcessesHolding(IReadOnlyCollection<string> files)
    {
        ArgumentNullException.ThrowIfNull(files);
        var paths = files.Where(f => !string.IsNullOrWhiteSpace(f)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (paths.Length == 0)
        {
            return [];
        }

        var sessionKey = new char[RmSessionKeyBufferLength];
        if (RmStartSession(out var session, 0, sessionKey) != ErrorSuccess)
        {
            return [];
        }
        try
        {
            if (RmRegisterResources(session, (uint)paths.Length, paths, 0, null, 0, null) != ErrorSuccess)
            {
                return [];
            }
            return ReadList(session);
        }
        finally
        {
            _ = RmEndSession(session);
        }
    }

    private static List<RestartManagerProcess> ReadList(uint session)
    {
        uint arraySize = 0;
        RmProcessInfo[] info = [];
        for (var attempt = 0; attempt < MaxProcessInfoAttempts; attempt++)
        {
            uint needed = 0;
            var count = arraySize;
            var status = RmGetList(session, out needed, ref count, info, out _);
            if (status == ErrorSuccess)
            {
                return Project(info, count);
            }
            if (status != ErrorMoreData || needed == 0)
            {
                return [];
            }
            arraySize = needed;
            info = new RmProcessInfo[arraySize];
        }
        return [];
    }

    private static List<RestartManagerProcess> Project(RmProcessInfo[] info, uint count)
    {
        var result = new List<RestartManagerProcess>((int)count);
        for (var i = 0; i < count && i < info.Length; i++)
        {
            var p = info[i];
            var ticks = ((long)p.Process.ProcessStartTime.dwHighDateTime << 32)
                | (uint)p.Process.ProcessStartTime.dwLowDateTime;
            result.Add(new RestartManagerProcess(p.Process.dwProcessId, ticks, p.strAppName ?? string.Empty));
        }
        return result;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RmFileTime
    {
        public int dwLowDateTime;
        public int dwHighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RmUniqueProcess
    {
        public int dwProcessId;
        public RmFileTime ProcessStartTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RmProcessInfo
    {
        public RmUniqueProcess Process;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] // CCH_RM_MAX_APP_NAME + 1
        public string strAppName;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] // CCH_RM_MAX_SVC_NAME + 1
        public string strServiceShortName;

        public int ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;

        [MarshalAs(UnmanagedType.Bool)]
        public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, [Out] char[] strSessionKey);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(
        uint pSessionHandle,
        uint nFiles,
        string[]? rgsFilenames,
        uint nApplications,
        RmUniqueProcess[]? rgApplications,
        uint nServices,
        string[]? rgsServiceNames);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmGetList(
        uint dwSessionHandle,
        out uint pnProcInfoNeeded,
        ref uint pnProcInfo,
        [In, Out] RmProcessInfo[] rgAffectedApps,
        out uint lpdwRebootReasons);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(uint pSessionHandle);
}
