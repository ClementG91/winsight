using System.Diagnostics;

using Xunit;

namespace WinSight.Response.Tests;

/// <summary>
/// The real Win32 inspector and controller against a spawned child process. These prove the actual OS
/// mechanism - capture, revalidation, suspend/resume, terminate - not a fake, on the current user's own
/// process without elevation.
/// </summary>
public sealed class Win32ProcessActionsTests
{
    private static readonly string PingLoop = OperatingSystem.IsWindows()
        ? Path.Combine(Environment.SystemDirectory, "cmd.exe")
        : "cmd.exe";

    private static Process StartChild() =>
        Process.Start(new ProcessStartInfo(PingLoop, "/c pause")
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            CreateNoWindow = true,
        })!;

    [Fact]
    public void CaptureRevalidatesTheSameProcessAndRejectsAWrongStartTime()
    {
        using var child = StartChild();
        try
        {
            var inspector = new Win32ProcessInspector();
            var captured = inspector.Capture(child.Id, hashImage: true);

            Assert.NotNull(captured);
            Assert.Equal(child.Id, captured!.Pid);
            Assert.Contains("cmd.exe", captured.ImagePath, StringComparison.OrdinalIgnoreCase);
            Assert.NotNull(captured.ImageSha256);

            var again = inspector.Capture(child.Id, hashImage: true);
            Assert.True(captured.Matches(again!));
            Assert.False(captured.Matches(captured with { StartTimestampUtcTicks = captured.StartTimestampUtcTicks + 1 }));
            Assert.Equal("cmd.exe", inspector.ImageFileName(child.Id), ignoreCase: true);
        }
        finally
        {
            child.Kill();
        }
    }

    [Fact]
    public void AResumedProcessRunsAgain()
    {
        // Outcomes alone are not enough: a suspend that raised each thread's suspend count twice
        // reported Succeeded for both verbs while the process stayed frozen for good. `pause` exits on
        // input only if its thread actually runs.
        using var child = StartChild();
        var controller = new Win32ProcessController();
        var identity = new Win32ProcessInspector().Capture(child.Id)!;
        try
        {
            Assert.Equal(ProcessControlOutcome.Succeeded, controller.SuspendThreads(identity));
            child.StandardInput.WriteLine();
            Assert.False(child.WaitForExit(1000), "a suspended process consumed its input");

            Assert.Equal(ProcessControlOutcome.Succeeded, controller.ResumeThreads(identity));
            Assert.True(child.WaitForExit(10_000), "the process is still frozen after resume");
        }
        finally
        {
            if (!child.HasExited)
            {
                controller.ResumeThreads(identity);
                child.Kill();
            }
        }
    }

    /// <summary>
    /// The controller itself refuses a process whose start time is not the captured one.
    /// </summary>
    /// <remarks>
    /// The responder revalidates before acting, but the action used to reopen the process by its bare
    /// pid, so a process that exited after the revalidation could hand its pid to an unrelated one
    /// that was then acted on. A different start time stands in for that successor here: the same pid,
    /// a different process. Nothing may be suspended or terminated, and the real process must keep
    /// running.
    /// </remarks>
    [Fact]
    public void AnIdentityWithAnotherStartTimeIsNeverActedOn()
    {
        using var child = StartChild();
        var controller = new Win32ProcessController();
        var captured = new Win32ProcessInspector().Capture(child.Id)!;
        var successor = captured with { StartTimestampUtcTicks = captured.StartTimestampUtcTicks + 1 };
        try
        {
            Assert.Equal(ProcessControlOutcome.TargetChanged, controller.SuspendThreads(successor));
            Assert.Equal(ProcessControlOutcome.TargetChanged, controller.TerminateProcess(successor));

            // Still running and not frozen: `pause` consumes the input and exits.
            child.StandardInput.WriteLine();
            Assert.True(child.WaitForExit(10_000), "a refused action still froze or killed the process");
            Assert.Equal(0, child.ExitCode);
        }
        finally
        {
            if (!child.HasExited)
            {
                controller.ResumeThreads(captured);
                child.Kill();
            }
        }
    }

    [Fact]
    public void SuspendResumeTerminateDriveARealChildProcess()
    {
        using var child = StartChild();
        var inspector = new Win32ProcessInspector();
        var controller = new Win32ProcessController();
        var responder = new ProcessResponder(inspector, controller,
            new ActionJournal(Path.Combine(Path.GetTempPath(), $"winsight-journal-{Guid.NewGuid():N}.jsonl")));
        var captured = inspector.Capture(child.Id)!;
        try
        {
            var suspend = responder.Suspend(captured, "cmd.exe");
            Assert.Equal(ResponseOutcome.Succeeded, suspend.Outcome);
            Assert.False(child.HasExited);

            var resume = responder.Resume(captured, "cmd.exe");
            Assert.Equal(ResponseOutcome.Succeeded, resume.Outcome);

            var terminate = responder.Terminate(captured, "cmd.exe");
            Assert.Equal(ResponseOutcome.Succeeded, terminate.Outcome);
            Assert.True(child.WaitForExit(5000));

            // The process has exited: it can never be suspended again. (While the test still holds an
            // open handle the pid is not reusable, so this is reported as a failed action rather than
            // "not found"; either way it is never Succeeded.)
            Assert.NotEqual(ResponseOutcome.Succeeded, responder.Suspend(captured, "cmd.exe").Outcome);
        }
        finally
        {
            if (!child.HasExited)
            {
                child.Kill();
            }
        }
    }
}
