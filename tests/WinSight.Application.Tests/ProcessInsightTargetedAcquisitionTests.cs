using System.Text.Json;

using WinSight.Core;
using WinSight.Modules;
using WinSight.NetMonitor;
using WinSight.Processes;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class ProcessInsightTargetedAcquisitionTests
{
    private const int TargetPid = 4242;
    private const long Birth = 638_900_000_000_000_000;
    private const string AbsenceAssertion = "A complete targeted absence must be reported as not running independently of unrelated global gaps.";

    [Fact]
    public void CompletedTargetAbsenceDoesNotInheritUnrelatedGlobalGaps()
    {
        var source = new RecordingSource
        {
            Target = new([]),
            Processes = new([], unreadableItems: 1),
        };
        using var cancellation = new CancellationTokenSource();

        var report = new ProcessInsightAcquirer(source).Acquire(TargetPid, cancellation.Token);

        Assert.True(report.Summary.Contains("not running", StringComparison.OrdinalIgnoreCase), AbsenceAssertion);
        Assert.Equal("pid 4242 is not running, or is not visible to this session", report.Summary);
        Assert.Empty(report.Items);
        Assert.Equal(["target:4242"], source.Calls);
        Assert.Equal([cancellation.Token], source.Tokens);
    }

    [Theory]
    [InlineData(1, 0)]
    [InlineData(0, 1)]
    [InlineData(1, 2)]
    public void IncompleteTargetAbsenceRemainsUnknownWithoutAFullScan(int unreadableSources, int unreadableItems)
    {
        var source = new RecordingSource
        {
            Target = new([], unreadableSources, unreadableItems),
            Processes = new([]),
        };

        var report = new ProcessInsightAcquirer(source).Acquire(TargetPid);

        Assert.Equal("pid 4242 was not observed; process enumeration was incomplete", report.Summary);
        var gap = Assert.Single(report.Items);
        Assert.Equal("acquisitionCoverage", gap.Fields["kind"]);
        Assert.Equal(["target:4242"], source.Calls);
    }

    [Fact]
    public void APositiveTargetUsesOnlyTheLatestFullSnapshotAndMatchingBirthIdentities()
    {
        var source = new RecordingSource
        {
            Target = new([Process(TargetPid, "obsolete.exe", 99, Birth - 100)], unreadableItems: 1),
            Processes = new([Process(100, "parent.exe", 4, Birth - 200),
                Process(TargetPid, "latest.exe", 100, Birth),
                Process(5001, "child.exe", TargetPid, Birth + 100)], unreadableItems: 2),
            Modules = new([Module("current.dll", Birth), Module("previous-birth.dll", Birth - 100)], unreadableSources: 1),
            Connections = [Connection("93.184.216.34:443", Birth), Connection("1.1.1.1:443", Birth - 100)],
        };
        using var cancellation = new CancellationTokenSource();

        var actual = new ProcessInsightAcquirer(source).Acquire(TargetPid, cancellation.Token);

        var expected = ProcessInsightReport.Render(TargetPid,
            ProcessInsightBuilder.Build(TargetPid, source.Processes.Items, source.Modules.Items, source.Connections),
            ProcessInsightCoverage.From(source.Processes, source.Modules));
        Assert.Equal(JsonSerializer.Serialize(expected), JsonSerializer.Serialize(actual));
        Assert.Equal(["target:4242", "processes", "modules:4242", "connections"], source.Calls);
        Assert.All(source.Tokens, token => Assert.Equal(cancellation.Token, token));
        Assert.Contains("latest.exe", actual.Items[0].Title, StringComparison.Ordinal);
        Assert.Contains(actual.Items, item => item.Detail.Contains("parent.exe", StringComparison.Ordinal)
            && item.Detail.Contains("child.exe", StringComparison.Ordinal));
        Assert.Contains(actual.Items, item => item.Title.Contains("current.dll", StringComparison.Ordinal));
        Assert.DoesNotContain(actual.Items, item => item.Title.Contains("obsolete.exe", StringComparison.Ordinal)
            || item.Title.Contains("previous-birth.dll", StringComparison.Ordinal)
            || item.Detail.Contains("1.1.1.1:443", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ATargetThatDisappearsUsesTheLatestFullCoverage(bool incomplete)
    {
        var source = new RecordingSource
        {
            Target = new([Process(TargetPid, "obsolete.exe", 99, Birth)]),
            Processes = new([], unreadableSources: incomplete ? 1 : 0),
        };

        var report = new ProcessInsightAcquirer(source).Acquire(TargetPid);

        Assert.Equal(incomplete
            ? "pid 4242 was not observed; process enumeration was incomplete"
            : "pid 4242 is not running, or is not visible to this session", report.Summary);
        Assert.Equal(["target:4242", "processes"], source.Calls);
        Assert.DoesNotContain(report.Items, item => item.Title.Contains("obsolete.exe", StringComparison.Ordinal));
    }

    [Fact]
    public void PrecancelledTargetAcquisitionDoesNotReadAnySource()
    {
        var source = new RecordingSource();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var failure = Assert.Throws<OperationCanceledException>(
            () => new ProcessInsightAcquirer(source).Acquire(TargetPid, cancellation.Token));

        Assert.Equal(cancellation.Token, failure.CancellationToken);
        Assert.Empty(source.Calls);
    }

    [Theory]
    [InlineData("target:4242", false)]
    [InlineData("processes", false)]
    [InlineData("modules:4242", false)]
    [InlineData("connections", false)]
    [InlineData("target:4242", true)]
    [InlineData("processes", true)]
    [InlineData("modules:4242", true)]
    [InlineData("connections", true)]
    public void TargetedAcquisitionErrorsPropagateWithoutLaterStages(string failingStage, bool cancelled)
    {
        using var cancellation = new CancellationTokenSource();
        Exception failure = cancelled
            ? new OperationCanceledException(cancellation.Token)
            : new InvalidOperationException("synthetic acquisition refusal");
        var source = new RecordingSource
        {
            Target = new([Process(TargetPid, "observed.exe", 100, Birth)]),
            Processes = new([Process(TargetPid, "latest.exe", 100, Birth)]),
            FailingStage = failingStage,
            Failure = failure,
            BeforeFailure = cancelled ? cancellation.Cancel : null,
        };

        var actual = Record.Exception(() => new ProcessInsightAcquirer(source).Acquire(TargetPid, cancellation.Token));

        Assert.Same(failure, actual);
        Assert.Equal(cancelled, cancellation.IsCancellationRequested);
        string[] stages = ["target:4242", "processes", "modules:4242", "connections"];
        Assert.Equal(stages.Take(Array.IndexOf(stages, failingStage) + 1), source.Calls);
        Assert.All(source.Tokens, token => Assert.Equal(cancellation.Token, token));
    }

    [Theory]
    [InlineData(-1, false)]
    [InlineData(-1, true)]
    [InlineData(int.MinValue, false)]
    [InlineData(int.MinValue, true)]
    public void NegativePidsRetainTheOriginalGlobalCoverageDecision(int pid, bool incomplete)
    {
        var source = new RecordingSource
        {
            Processes = new([], unreadableSources: incomplete ? 1 : 0),
            FailingStage = "target:" + pid,
            Failure = new InvalidOperationException("negative PID must bypass the targeted API"),
        };

        var report = new ProcessInsightAcquirer(source).Acquire(pid);

        Assert.Equal(incomplete
            ? $"pid {pid} was not observed; process enumeration was incomplete"
            : $"pid {pid} is not running, or is not visible to this session", report.Summary);
        Assert.Equal(["processes"], source.Calls);
    }

    [Fact]
    public void ZeroPidUsesTargetCoverageWithoutBeingTreatedAsNegative()
    {
        var source = new RecordingSource { Target = new([], unreadableSources: 1) };

        var report = new ProcessInsightAcquirer(source).Acquire(0);

        Assert.Equal("pid 0 was not observed; process enumeration was incomplete", report.Summary);
        Assert.Equal(["target:0"], source.Calls);
    }

    private static ProcessInfo Process(int pid, string name, int parentPid, long birth) =>
        new(pid, name, null, parentPid, null, SignatureVerdict.Unsigned) { StartTimestampUtcTicks = birth };

    private static LoadedModule Module(string name, long birth) =>
        new(TargetPid, "latest.exe", name, $@"C:\Program Files\WinSight-Fixtures\{name}", SignatureVerdict.Unsigned)
        { ProcessStartTimestampUtcTicks = birth };

    private static Connection Connection(string remote, long birth) =>
        new("TCP", "10.0.0.5:5000", remote, "ESTABLISHED", TargetPid, "latest.exe", null, SignatureVerdict.Unsigned)
        { ProcessStartTimestampUtcTicks = birth };

    private sealed class RecordingSource : IProcessInsightAcquisition
    {
        internal AcquisitionSnapshot<ProcessInfo> Target { get; init; } = new([]);
        internal AcquisitionSnapshot<ProcessInfo> Processes { get; init; } = new([]);
        internal AcquisitionSnapshot<LoadedModule> Modules { get; init; } = new([]);
        internal IReadOnlyList<Connection> Connections { get; init; } = [];
        internal string? FailingStage { get; init; }
        internal Exception? Failure { get; init; }
        internal Action? BeforeFailure { get; init; }
        internal List<string> Calls { get; } = [];
        internal List<CancellationToken> Tokens { get; } = [];

        // An extra ordinary member before the production interface gains this contract.
        public AcquisitionSnapshot<ProcessInfo> AcquireTargetProcess(int pid, CancellationToken cancellationToken)
        {
            Enter("target:" + pid, cancellationToken);
            return Target;
        }

        public AcquisitionSnapshot<ProcessInfo> GetProcesses(CancellationToken cancellationToken)
        {
            Enter("processes", cancellationToken);
            return Processes;
        }

        public AcquisitionSnapshot<LoadedModule> GetModules(int pid, CancellationToken cancellationToken)
        {
            Enter("modules:" + pid, cancellationToken);
            return Modules;
        }

        public IReadOnlyList<Connection> GetConnections(CancellationToken cancellationToken)
        {
            Enter("connections", cancellationToken);
            return Connections;
        }

        private void Enter(string stage, CancellationToken cancellationToken)
        {
            Calls.Add(stage);
            Tokens.Add(cancellationToken);
            if (stage == FailingStage)
            {
                BeforeFailure?.Invoke();
                throw Failure!;
            }
        }
    }
}
