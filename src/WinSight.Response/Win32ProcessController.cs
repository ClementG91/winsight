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
/// <b>Every action goes through one process handle that was checked against the identity.</b> The
/// responder revalidates the captured identity and then asks for the action; opening the process
/// again by its bare pid for the action itself re-opened the window the revalidation exists to close,
/// because a pid is reused the moment its process exits. A process handle keeps the process object -
/// and therefore its pid - from being reused while it is open, so the handle is opened once, its
/// creation time is compared with the captured one, and it is held until the action is done. Threads
/// are only acted on after confirming, through their own handle, that they belong to that process.
///
/// <b>Success means every live thread.</b> Suspension used to report success as soon as any one
/// thread was suspended, and a thread that could not be opened was marked handled and never retried,
/// so the operator could be told a process was frozen while one of its threads kept running. A thread
/// that exits between the snapshot and the open is not a failure; any other thread that cannot be
/// acted on is. A failed suspension resumes the threads it had already suspended through the same
/// still-open handles; if any live thread cannot be proven resumed, the controller returns
/// <see cref="ProcessControlOutcome.RollbackIncomplete"/> instead of pretending the action was a no-op.
///
/// The thread-by-thread route uses only documented Win32 (<c>CreateToolhelp32Snapshot</c>,
/// <c>OpenThread</c>, <c>GetProcessIdOfThread</c>, <c>SuspendThread</c>/<c>ResumeThread</c>). The
/// undocumented <c>NtSuspendProcess</c> would be shorter, but this project's rule is to prefer a
/// documented API and not to build on an undocumented one. Callers must have already refused
/// protected processes; this class only performs the mechanism.
/// </remarks>
public sealed class Win32ProcessController : IProcessController
{
    private const uint ThreadSuspendResume = 0x0002;
    private const uint ThreadQueryLimitedInformation = 0x0800;
    private const uint ProcessTerminate = 0x0001;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint Th32csSnapThread = 0x00000004;
    private const int ErrorInvalidParameter = 87;
    private const uint StillActive = 259;
    private const int MaxPasses = 8;

    public ProcessControlOutcome SuspendThreads(ProcessIdentity expected) =>
        WithVerifiedProcess(expected, ProcessQueryLimitedInformation, _ => SuspendAll(expected.Pid));

    public ProcessControlOutcome ResumeThreads(ProcessIdentity expected) =>
        WithVerifiedProcess(expected, ProcessQueryLimitedInformation, _ =>
            ForEachThreadOnce(expected.Pid, ResumeThread, []) is { Failed: false, Touched.Count: > 0 }
                ? ProcessControlOutcome.Succeeded
                : ProcessControlOutcome.Failed);

    public ProcessControlOutcome TerminateProcess(ProcessIdentity expected) =>
        WithVerifiedProcess(expected, ProcessTerminate | ProcessQueryLimitedInformation,
            process => TerminateProcess(process, 1)
                ? ProcessControlOutcome.Succeeded
                : ProcessControlOutcome.Failed);

    /// <summary>
    /// Opens the process once, confirms it is the one <paramref name="expected"/> describes, and runs
    /// <paramref name="action"/> while that handle - and so the pid - is held.
    /// </summary>
    private static ProcessControlOutcome WithVerifiedProcess(
        ProcessIdentity expected, uint access, Func<SafeProcessHandle, ProcessControlOutcome> action)
    {
        ArgumentNullException.ThrowIfNull(expected);
        try
        {
            using var process = OpenProcess(access, false, expected.Pid);
            if (process.IsInvalid
                || !GetProcessTimes(process, out var creation, out _, out _, out _))
            {
                return ProcessControlOutcome.Failed;
            }
            if (ToTicks(creation) != expected.StartTimestampUtcTicks)
            {
                return ProcessControlOutcome.TargetChanged;
            }
            return action(process);
        }
        catch (Win32Exception)
        {
            return ProcessControlOutcome.Failed;
        }
    }

    private static ProcessControlOutcome SuspendAll(int pid)
    {
        var suspended = new List<SafeThreadHandle>();
        var seen = new HashSet<int>();
        try
        {
            for (var pass = 0; pass < MaxPasses; pass++)
            {
                var result = SuspendPass(pid, seen);
                suspended.AddRange(result.Suspended);
                if (result.Failed)
                {
                    return Rollback(suspended)
                        ? ProcessControlOutcome.Failed
                        : ProcessControlOutcome.RollbackIncomplete;
                }
                if (result.Suspended.Count == 0)
                {
                    // No thread left that this call has not already suspended.
                    return suspended.Count > 0
                        ? ProcessControlOutcome.Succeeded
                        : ProcessControlOutcome.Failed;
                }
            }
            // Still finding new threads after every pass: the process is spawning faster than it can
            // be frozen. Reporting that as success would be the claim this class exists not to make.
            return Rollback(suspended)
                ? ProcessControlOutcome.Failed
                : ProcessControlOutcome.RollbackIncomplete;
        }
        finally
        {
            foreach (var thread in suspended)
            {
                thread.Dispose();
            }
        }
    }

    private static SuspendPassResult SuspendPass(int pid, HashSet<int> seen)
    {
        var suspended = new List<SafeThreadHandle>();
        foreach (var tid in ThreadIds(pid))
        {
            if (seen.Contains(tid))
            {
                continue;
            }
            var thread = OpenThread(ThreadSuspendResume | ThreadQueryLimitedInformation, false, tid);
            if (thread.IsInvalid)
            {
                thread.Dispose();
                if (Marshal.GetLastPInvokeError() == ErrorInvalidParameter)
                {
                    seen.Add(tid);
                    continue;
                }
                return new SuspendPassResult(suspended, Failed: true);
            }
            if (GetProcessIdOfThread(thread) != (uint)pid)
            {
                seen.Add(tid);
                thread.Dispose();
                continue;
            }
            if (SuspendThread(thread) == uint.MaxValue)
            {
                thread.Dispose();
                return new SuspendPassResult(suspended, Failed: true);
            }
            seen.Add(tid);
            suspended.Add(thread); // held through success or rollback; never reopened by bare tid
        }
        return new SuspendPassResult(suspended, Failed: false);
    }

    private static bool Rollback(List<SafeThreadHandle> suspended)
    {
        var complete = true;
        for (var index = suspended.Count - 1; index >= 0; index--)
        {
            var thread = suspended[index];
            if (ResumeThread(thread) != uint.MaxValue)
            {
                continue;
            }
            // A thread that has exited cannot remain suspended. Failure on a still-live thread is a
            // partial action and must be surfaced to the operator.
            if (!GetExitCodeThread(thread, out var exitCode) || exitCode == StillActive)
            {
                complete = false;
            }
        }
        return complete;
    }

    private readonly record struct SuspendPassResult(List<SafeThreadHandle> Suspended, bool Failed);
    private readonly record struct PassResult(List<int> Touched, bool Failed);

    /// <summary>
    /// Acts once on every thread of <paramref name="pid"/> not already in <paramref name="seen"/>.
    /// A thread is added to <paramref name="seen"/> only once it has been acted on, or once it is
    /// known to have exited, so a transient failure is reported rather than silently skipped.
    /// </summary>
    private static PassResult ForEachThreadOnce(int pid, Func<SafeThreadHandle, uint> operation, HashSet<int> seen)
    {
        var touched = new List<int>();
        foreach (var tid in ThreadIds(pid))
        {
            if (seen.Contains(tid))
            {
                continue;
            }
            using var thread = OpenThread(ThreadSuspendResume | ThreadQueryLimitedInformation, false, tid);
            if (thread.IsInvalid)
            {
                if (Marshal.GetLastPInvokeError() == ErrorInvalidParameter)
                {
                    seen.Add(tid); // exited between the snapshot and the open
                    continue;
                }
                return new PassResult(touched, Failed: true);
            }
            // A thread id is reused like a pid; the snapshot's owner is only a claim until the
            // handle confirms it. The process handle the caller holds keeps the pid itself stable.
            if (GetProcessIdOfThread(thread) != (uint)pid)
            {
                seen.Add(tid);
                continue;
            }
            if (operation(thread) == uint.MaxValue)
            {
                return new PassResult(touched, Failed: true);
            }
            seen.Add(tid);
            touched.Add(tid);
        }
        return new PassResult(touched, Failed: false);
    }

    private static long ToTicks(FileTime time) =>
        ((long)time.dwHighDateTime << 32) | (uint)time.dwLowDateTime;

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

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public int dwLowDateTime;
        public int dwHighDateTime;
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
    private static extern uint GetProcessIdOfThread(SafeThreadHandle thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint SuspendThread(SafeThreadHandle thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(SafeThreadHandle thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeThread(SafeThreadHandle thread, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(
        SafeProcessHandle process, out FileTime creation, out FileTime exit, out FileTime kernel, out FileTime user);

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
