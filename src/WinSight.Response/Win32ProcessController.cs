using System.ComponentModel;
using System.Runtime.InteropServices;

using Microsoft.Win32.SafeHandles;

namespace WinSight.Response;

/// <summary>
/// The production <see cref="IProcessController"/>. Suspension enumerates the process's threads and
/// suspends each exactly once, repeating until a pass finds no thread it has not already suspended, so
/// a thread created during the pass is caught too. Resumption resumes each thread once. Termination
/// uses <c>TerminateProcess</c>.
/// </summary>
/// <remarks>
/// <c>SuspendThread</c> increments a per-thread count that <c>ResumeThread</c> decrements, so the two
/// must stay balanced: suspending a thread twice and resuming it once leaves the process frozen while
/// both calls report success.
/// </remarks>
/// <remarks>
/// The thread-by-thread route uses only documented Win32 (<c>CreateToolhelp32Snapshot</c>,
/// <c>OpenThread</c>, <c>SuspendThread</c>/<c>ResumeThread</c>). The undocumented
/// <c>NtSuspendProcess</c> would be shorter, but this project's rule is to prefer a documented API and
/// not to build on an undocumented one. Callers must have already refused protected processes and
/// revalidated identity; this class only performs the mechanism.
/// </remarks>
public sealed class Win32ProcessController : IProcessController
{
    private const uint ThreadSuspendResume = 0x0002;
    private const uint ProcessTerminate = 0x0001;
    private const uint Th32csSnapThread = 0x00000004;
    private const int MaxPasses = 8;

    public bool SuspendThreads(int pid) => ForEachThread(pid, SuspendThread, untilNoNewThread: true);

    public bool ResumeThreads(int pid) => ForEachThread(pid, ResumeThread, untilNoNewThread: false);

    public bool TerminateProcess(int pid)
    {
        try
        {
            using var handle = OpenProcess(ProcessTerminate, false, pid);
            return !handle.IsInvalid && TerminateProcess(handle, 1);
        }
        catch (Win32Exception)
        {
            return false;
        }
    }

    private static bool ForEachThread(int pid, Func<SafeThreadHandle, uint> operation, bool untilNoNewThread)
    {
        var touchedAny = false;
        // Each thread is acted on at most once, whatever the number of passes.
        var handled = new HashSet<int>();
        try
        {
            for (var pass = 0; pass < MaxPasses; pass++)
            {
                var newThreads = ThreadIds(pid).Where(handled.Add).ToList();
                if (newThreads.Count == 0)
                {
                    return touchedAny; // no thread left to act on, or the process has exited
                }
                foreach (var tid in newThreads)
                {
                    using var thread = OpenThread(ThreadSuspendResume, false, tid);
                    if (!thread.IsInvalid && operation(thread) != uint.MaxValue)
                    {
                        touchedAny = true;
                    }
                }
                // For suspend, a thread spawned by a still-running thread during the pass is caught by
                // the next one. Resume needs only a single pass.
                if (!untilNoNewThread)
                {
                    return touchedAny;
                }
            }
            return touchedAny;
        }
        catch (Win32Exception)
        {
            return touchedAny;
        }
    }

    private static List<int> ThreadIds(int pid)
    {
        var ids = new List<int>();
        using var snapshot = CreateToolhelp32Snapshot(Th32csSnapThread, 0);
        if (snapshot.IsInvalid)
        {
            return ids;
        }
        var entry = new ThreadEntry32 { dwSize = (uint)Marshal.SizeOf<ThreadEntry32>() };
        if (!Thread32First(snapshot, ref entry))
        {
            return ids;
        }
        do
        {
            if (entry.th32OwnerProcessID == pid)
            {
                ids.Add((int)entry.th32ThreadID);
            }
        }
        while (Thread32Next(snapshot, ref entry));
        return ids;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ThreadEntry32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ThreadID;
        public uint th32OwnerProcessID;
        public int tpBasePri;
        public int tpDeltaPri;
        public uint dwFlags;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeSnapshotHandle CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Thread32First(SafeSnapshotHandle snapshot, ref ThreadEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Thread32Next(SafeSnapshotHandle snapshot, ref ThreadEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeThreadHandle OpenThread(uint desiredAccess, bool inheritHandle, int threadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint SuspendThread(SafeThreadHandle thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(SafeThreadHandle thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);

    private sealed class SafeThreadHandle() : SafeHandleZeroOrMinusOneIsInvalid(true)
    {
        protected override bool ReleaseHandle() => CloseHandle(handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
    }

    private sealed class SafeSnapshotHandle() : SafeHandleZeroOrMinusOneIsInvalid(true)
    {
        protected override bool ReleaseHandle() => CloseHandle(handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
    }
}
