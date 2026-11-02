using System.Text.Json;

using WinSight.Core;
using WinSight.Modules;
using WinSight.NetMonitor;
using WinSight.Processes;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class ProcessInsightAcquirerTests
{
    private const int TargetPid = 4242;
    private const long Birth = 638_900_000_000_000_000;

    [Fact]
    public void ConstructionDoesNotAcquireAnything()
    {
        var source = new RecordingSource();

        _ = new ProcessInsightAcquirer(source);
        _ = new NativeProcessInsightAcquisition(new NeverCalledVerifier());

        Assert.Empty(source.Calls);
    }

    [Fact]
    public void CompleteAbsenceReturnsBeforeModulesAndConnections()
    {
        var source = new RecordingSource();

        var report = new ProcessInsightAcquirer(source).Acquire(TargetPid);

        Assert.Equal("process", report.Tool);
        Assert.Equal("pid 4242 is not running, or is not visible to this session", report.Summary);
        Assert.Empty(report.Items);
        Assert.Equal(["processes"], source.Calls);
    }

    [Theory]
    [InlineData(1, 0)]
    [InlineData(0, 1)]
    public void IncompleteAbsenceRetainsUnknownCoverage(int unreadableSources, int unreadableItems)
    {
        var source = new RecordingSource
        {
            Processes = new([], unreadableSources, unreadableItems),
        };

        var report = new ProcessInsightAcquirer(source).Acquire(TargetPid);

        Assert.Equal("pid 4242 was not observed; process enumeration was incomplete", report.Summary);
        var gap = Assert.Single(report.Items);
        Assert.Equal("acquisitionCoverage", gap.Fields["kind"]);
        Assert.Equal(["processes"], source.Calls);
    }

    [Fact]
    public void LiveAcquisitionKeepsFullLineageIdentityCoverageAndOrder()
    {
        var source = new RecordingSource
        {
            Processes = new([Process(100, "parent.exe", 4, Birth - 20),
                Process(TargetPid, "target.exe", 100, Birth),
                Process(5001, "child.exe", TargetPid, Birth + 20)], unreadableItems: 1),
            Modules = new([Module("current.dll", Birth), Module("reused.dll", Birth - 1)], unreadableSources: 1),
            Connections = [Connection("93.184.216.34:443", Birth), Connection("1.1.1.1:443", Birth - 1)],
        };
        using var cancellation = new CancellationTokenSource();

        var actual = new ProcessInsightAcquirer(source).Acquire(TargetPid, cancellation.Token);

        var expected = ProcessInsightReport.Render(TargetPid,
            ProcessInsightBuilder.Build(TargetPid, source.Processes.Items, source.Modules.Items, source.Connections),
            ProcessInsightCoverage.From(source.Processes, source.Modules));
        Assert.Equal(JsonSerializer.Serialize(expected), JsonSerializer.Serialize(actual));
        Assert.Equal(["processes", "modules:4242", "connections"], source.Calls);
        Assert.All(source.Tokens, token => Assert.Equal(cancellation.Token, token));
        Assert.Contains(actual.Items, item => item.Detail.Contains("parent.exe", StringComparison.Ordinal)
            && item.Detail.Contains("child.exe", StringComparison.Ordinal));
        Assert.Contains(actual.Items, item => item.Title.Contains("current.dll", StringComparison.Ordinal));
        Assert.DoesNotContain(actual.Items, item => item.Title.Contains("reused.dll", StringComparison.Ordinal)
            || item.Detail.Contains("1.1.1.1:443", StringComparison.Ordinal));
    }

    [Fact]
    public void PrecancelledAcquisitionDoesNotReadAnySource()
    {
        var source = new RecordingSource();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var error = Assert.Throws<OperationCanceledException>(
            () => new ProcessInsightAcquirer(source).Acquire(TargetPid, cancellation.Token));

        Assert.Equal(cancellation.Token, error.CancellationToken);
        Assert.Empty(source.Calls);
    }

    [Theory]
    [InlineData("processes", false)]
    [InlineData("modules:4242", false)]
    [InlineData("connections", false)]
    [InlineData("processes", true)]
    [InlineData("modules:4242", true)]
    [InlineData("connections", true)]
    public void AcquisitionErrorsAndCancellationPropagateAtTheSameStage(string failingStage, bool cancelled)
    {
        using var cancellation = new CancellationTokenSource();
        Exception failure = cancelled
            ? new OperationCanceledException(cancellation.Token)
            : new InvalidOperationException("synthetic acquisition refusal");
        var source = new RecordingSource
        {
            Processes = new([Process(TargetPid, "target.exe", 100, Birth)]),
            FailingStage = failingStage,
            Failure = failure,
        };

        var actual = Record.Exception(() => new ProcessInsightAcquirer(source).Acquire(TargetPid, cancellation.Token));

        Assert.Same(failure, actual);
        string[] stages = ["processes", "modules:4242", "connections"];
        Assert.Equal(stages.Take(Array.IndexOf(stages, failingStage) + 1), source.Calls);
        Assert.All(source.Tokens, token => Assert.Equal(cancellation.Token, token));
    }

    private static ProcessInfo Process(int pid, string name, int parentPid, long birth) =>
        new(pid, name, null, parentPid, null, SignatureVerdict.Unsigned) { StartTimestampUtcTicks = birth };

    private static LoadedModule Module(string name, long birth) =>
        new(TargetPid, "target.exe", name, $@"C:\Program Files\WinSight-Fixtures\{name}", SignatureVerdict.Unsigned) { ProcessStartTimestampUtcTicks = birth };

    private static Connection Connection(string remote, long birth) =>
        new("TCP", "10.0.0.5:5000", remote, "ESTABLISHED", TargetPid, "target.exe", null, SignatureVerdict.Unsigned)
        { ProcessStartTimestampUtcTicks = birth };

    private sealed class RecordingSource : IProcessInsightAcquisition
    {
        internal AcquisitionSnapshot<ProcessInfo> Processes { get; init; } = new([]);
        internal AcquisitionSnapshot<LoadedModule> Modules { get; init; } = new([]);
        internal IReadOnlyList<Connection> Connections { get; init; } = [];
        internal string? FailingStage { get; init; }
        internal Exception? Failure { get; init; }
        internal List<string> Calls { get; } = [];
        internal List<CancellationToken> Tokens { get; } = [];

        // These cases isolate the original stages after a positive target lookup.
        // The separate targeted-acquisition cases record and verify the new first stage.
        public AcquisitionSnapshot<ProcessInfo> AcquireTargetProcess(int pid, CancellationToken cancellationToken) =>
            new([Process(pid, "synthetic-target.exe", 0, Birth)]);

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
                throw Failure!;
            }
        }
    }

    private sealed class NeverCalledVerifier : ISignatureVerifier
    {
        public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("construction must not verify an image");

        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("construction must not verify images");
    }
}
