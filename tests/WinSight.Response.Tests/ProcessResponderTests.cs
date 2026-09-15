using Xunit;

namespace WinSight.Response.Tests;

public sealed class ProcessResponderTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 14, 12, 0, 0, TimeSpan.Zero);

    private static ProcessIdentity Identity(int pid = 4321, long start = 100, string path = @"C:\app\evil.exe", string? hash = null) =>
        new(pid, start, path, hash);

    private static ProcessResponder Responder(FakeInspector inspector, FakeController controller, string journal) =>
        new(inspector, controller, new ActionJournal(journal), () => T0);

    [Fact]
    public void SuspendActsWhenTheProcessIsStillTheOneCaptured()
    {
        var captured = Identity();
        var inspector = new FakeInspector { Current = captured, FileName = "evil.exe" };
        var controller = new FakeController();
        using var journal = new TempFile();

        var result = Responder(inspector, controller, journal.Path).Suspend(captured, "evil.exe");

        Assert.Equal(ResponseOutcome.Succeeded, result.Outcome);
        Assert.True(result.Reversible);
        Assert.Equal([captured.Pid], controller.Suspended);
        var entry = Assert.Single(new ActionJournal(journal.Path).Read());
        Assert.Equal(result.ActionId, entry.ActionId);
        Assert.Equal(ResponseActionKind.SuspendProcess, entry.Kind);
    }

    [Fact]
    public void AReusedPidWithADifferentStartTimeIsRefusedAsChanged()
    {
        var captured = Identity(start: 100);
        var inspector = new FakeInspector { Current = captured with { StartTimestampUtcTicks = 999 }, FileName = "other.exe" };
        var controller = new FakeController();
        using var journal = new TempFile();

        var result = Responder(inspector, controller, journal.Path).Terminate(captured, "evil.exe");

        Assert.Equal(ResponseOutcome.TargetChanged, result.Outcome);
        Assert.Empty(controller.Terminated);
    }

    [Fact]
    public void AReplacedImageHashIsRefusedAsChanged()
    {
        var captured = Identity(hash: "AAAA");
        var inspector = new FakeInspector { Current = captured with { ImageSha256 = "BBBB" }, FileName = "evil.exe" };
        var controller = new FakeController();
        using var journal = new TempFile();

        var result = Responder(inspector, controller, journal.Path).Suspend(captured, "evil.exe");

        Assert.Equal(ResponseOutcome.TargetChanged, result.Outcome);
        Assert.Empty(controller.Suspended);
    }

    [Fact]
    public void AProcessThatExitedIsRefusedAsNotFound()
    {
        var captured = Identity();
        var inspector = new FakeInspector { Current = null, FileName = "evil.exe" };
        var controller = new FakeController();
        using var journal = new TempFile();

        var result = Responder(inspector, controller, journal.Path).Terminate(captured, "evil.exe");

        Assert.Equal(ResponseOutcome.TargetNotFound, result.Outcome);
    }

    [Theory]
    [InlineData(0, "System Idle Process")]
    [InlineData(4, "System")]
    [InlineData(9000, "lsass.exe")]
    [InlineData(9000, "winsight-dashboard.exe")]
    public void AProtectedProcessIsNeverActedOn(int pid, string fileName)
    {
        var captured = Identity(pid: pid);
        var inspector = new FakeInspector { Current = captured, FileName = fileName };
        var controller = new FakeController();
        using var journal = new TempFile();

        var result = Responder(inspector, controller, journal.Path).Terminate(captured, fileName);

        Assert.Equal(ResponseOutcome.TargetProtected, result.Outcome);
        Assert.Empty(controller.Terminated);
        Assert.Empty(controller.Suspended);
    }

    [Fact]
    public void AControllerFailureIsReportedAsFailedAndJournalled()
    {
        var captured = Identity();
        var inspector = new FakeInspector { Current = captured, FileName = "evil.exe" };
        var controller = new FakeController { Succeed = false };
        using var journal = new TempFile();

        var result = Responder(inspector, controller, journal.Path).Suspend(captured, "evil.exe");

        Assert.Equal(ResponseOutcome.Failed, result.Outcome);
        Assert.False(result.Reversible);
        Assert.Equal(ResponseOutcome.Failed, Assert.Single(new ActionJournal(journal.Path).Read()).Outcome);
    }

    [Fact]
    public void ResumeUndoesASuspensionAndIsRecordedSeparately()
    {
        var captured = Identity();
        var inspector = new FakeInspector { Current = captured, FileName = "evil.exe" };
        var controller = new FakeController();
        using var journal = new TempFile();
        var responder = Responder(inspector, controller, journal.Path);

        responder.Suspend(captured, "evil.exe");
        var resume = responder.Resume(captured, "evil.exe");

        Assert.Equal(ResponseOutcome.Succeeded, resume.Outcome);
        Assert.Equal([captured.Pid], controller.Resumed);
        Assert.Equal(2, new ActionJournal(journal.Path).Read().Count);
    }

    private sealed class FakeInspector : IProcessInspector
    {
        public ProcessIdentity? Current { get; set; }
        public string? FileName { get; set; }
        public ProcessIdentity? Capture(int pid, bool hashImage = false) => Current;
        public string? ImageFileName(int pid) => FileName;
    }

    private sealed class FakeController : IProcessController
    {
        public bool Succeed { get; set; } = true;
        public List<int> Suspended { get; } = [];
        public List<int> Resumed { get; } = [];
        public List<int> Terminated { get; } = [];
        public bool SuspendThreads(int pid) { if (Succeed) { Suspended.Add(pid); } return Succeed; }
        public bool ResumeThreads(int pid) { if (Succeed) { Resumed.Add(pid); } return Succeed; }
        public bool TerminateProcess(int pid) { if (Succeed) { Terminated.Add(pid); } return Succeed; }
    }
}

internal sealed class TempFile : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(
        System.IO.Path.GetTempPath(), $"winsight-response-{Guid.NewGuid():N}");

    public void Dispose()
    {
        try
        {
            if (File.Exists(Path))
            {
                File.Delete(Path);
            }
        }
        catch (IOException)
        {
        }
    }
}
