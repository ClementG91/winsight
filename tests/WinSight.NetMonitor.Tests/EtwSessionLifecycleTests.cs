using Microsoft.Diagnostics.Tracing.Session;
using WinSight.NetMonitor;
using Xunit;

namespace WinSight.NetMonitor.Tests;

/// <summary>
/// Exercises lifecycle decisions through a fully managed runtime fake. A unit test must never
/// enumerate or stop the machine-global ETW namespace: these assertions prove the security
/// policy around the native boundary, while the VM gate proves TraceEvent itself.
/// </summary>
public sealed class EtwSessionLifecycleTests
{
    private const int CurrentPid = 9001;
    private const string CurrentStart = "0123456789ABCDEF";
    private const string OtherStart = "FEDCBA9876543210";

    [Theory]
    [InlineData(0, "WinSight-Attribution-v2-9001-0123456789ABCDEF")]
    [InlineData(1, "WinSight-Outbound-v2-9001-0123456789ABCDEF")]
    [InlineData(2, "WinSight-DNS-v2-9001-0123456789ABCDEF")]
    public void EachClosedProfileCreatesAVersionedSessionWithoutRestartingAnything(
        int profileValue,
        string expectedName)
    {
        var runtime = new FakeRuntime();
        var lifecycle = new EtwSessionLifecycle(runtime, new FakeProcesses());

        lifecycle.Open((EtwSessionProfile)profileValue);

        var created = Assert.Single(runtime.Created);
        Assert.Equal(expectedName, created.Name);
        Assert.Equal(
            TraceEventSessionOptions.Create | TraceEventSessionOptions.NoRestartOnCreate,
            created.Options);
        Assert.Empty(runtime.Attached);
    }

    [Fact]
    public void CurrentLiveAmbiguousMalformedAndOtherProfileSessionsAreNeverAttached()
    {
        var runtime = new FakeRuntime(
            "WinSight-Attribution-9001",
            "WinSight-Attribution-41",
            "WinSight-Attribution-v2-42-FEDCBA9876543210",
            "WinSight-Attribution-v2-43-0123456789ABCDEF",
            "WinSight-Attribution-v2-0-0123456789ABCDEF",
            "WinSight-Attribution-v2-44-not-hex",
            "WinSight-Attribution-v2-45-0123456789abcdef",
            "WinSight-Attribution-v2-45-0123456789ABCDEF-extra",
            "WinSight-Attribution-45x",
            "WinSight-Attribution-v3-46-0123456789ABCDEF",
            "WinSight-Outbound-47",
            "NotWinSight-Attribution-48");
        var processes = new FakeProcesses
        {
            States =
            {
                [41] = Sequence(EtwOwnerState.Matches),
                [42] = Sequence(EtwOwnerState.Matches),
                [43] = Sequence(EtwOwnerState.Indeterminate),
            },
        };
        var lifecycle = new EtwSessionLifecycle(runtime, processes);

        lifecycle.Open(EtwSessionProfile.Attribution);

        Assert.Empty(runtime.Attached);
        Assert.Empty(runtime.Stopped);
    }

    [Fact]
    public void AProvenDeadLegacySessionIsAttachedRecheckedAndExplicitlyStopped()
    {
        const string stale = "WinSight-Attribution-77";
        var runtime = new FakeRuntime(stale);
        var processes = new FakeProcesses { States = { [77] = Sequence(EtwOwnerState.Absent, EtwOwnerState.Absent) } };
        var lifecycle = new EtwSessionLifecycle(runtime, processes);

        lifecycle.Open(EtwSessionProfile.Attribution);

        Assert.Equal([stale], runtime.Attached);
        Assert.Equal([stale], runtime.Stopped);
        Assert.DoesNotContain(stale, runtime.Active);
    }

    [Fact]
    public void AReusedPidWithDifferentV2StartIdentityIsReclaimed()
    {
        const string stale = "WinSight-DNS-v2-78-FEDCBA9876543210";
        var runtime = new FakeRuntime(stale);
        var processes = new FakeProcesses { States = { [78] = Sequence(EtwOwnerState.Mismatch, EtwOwnerState.Mismatch) } };
        var lifecycle = new EtwSessionLifecycle(runtime, processes);

        lifecycle.Open(EtwSessionProfile.Dns);

        Assert.Equal([stale], runtime.Stopped);
        Assert.DoesNotContain(stale, runtime.Active);
    }

    [Fact]
    public void AForcedKilledV2OwnerIsReclaimedWithAnObservedDisappearance()
    {
        const string stale = "WinSight-DNS-v2-780-FEDCBA9876543210";
        var runtime = new FakeRuntime(stale);
        var lifecycle = new EtwSessionLifecycle(
            runtime,
            new FakeProcesses { States = { [780] = Sequence(EtwOwnerState.Absent, EtwOwnerState.Absent) } });

        var results = lifecycle.ReclaimProvenOrphans(EtwSessionProfile.Dns);

        Assert.Equal([new EtwCleanupResult(stale, Disappeared: true)], results);
        Assert.Equal([stale], runtime.Attached);
        Assert.Equal([true], runtime.StopArguments);
        Assert.Equal(2, runtime.GetCalls);
    }

    [Fact]
    public void ACandidateWithTheCurrentPidButADifferentV2StartIdentityIsReclaimed()
    {
        // A PID is reusable. The current process owns only the session with its own start
        // identity, not an older session that happens to carry the PID Windows has since reused.
        const string stale = "WinSight-Attribution-v2-9001-FEDCBA9876543210";
        var runtime = new FakeRuntime(stale);
        var processes = new FakeProcesses
        {
            States = { [CurrentPid] = Sequence(EtwOwnerState.Mismatch, EtwOwnerState.Mismatch) },
        };
        var lifecycle = new EtwSessionLifecycle(runtime, processes);

        lifecycle.Open(EtwSessionProfile.Attribution);

        Assert.Equal([stale], runtime.Stopped);
    }

    [Fact]
    public void AProcessThatAppearsDuringTheSecondProbeIsPreserved()
    {
        const string contested = "WinSight-Outbound-79";
        var runtime = new FakeRuntime(contested);
        var processes = new FakeProcesses
        {
            States = { [79] = Sequence(EtwOwnerState.Absent, EtwOwnerState.Matches) },
        };
        var lifecycle = new EtwSessionLifecycle(runtime, processes);

        lifecycle.Open(EtwSessionProfile.Outbound);

        Assert.Equal([contested], runtime.Attached);
        Assert.Empty(runtime.Stopped);
        Assert.Contains(contested, runtime.Active);
    }

    [Fact]
    public void AV2OwnerThatAppearsDuringTheSecondProbeIsPreserved()
    {
        const string contested = "WinSight-Outbound-v2-790-FEDCBA9876543210";
        var runtime = new FakeRuntime(contested);
        var processes = new FakeProcesses
        {
            States = { [790] = Sequence(EtwOwnerState.Absent, EtwOwnerState.Matches) },
        };
        var lifecycle = new EtwSessionLifecycle(runtime, processes);

        var results = lifecycle.ReclaimProvenOrphans(EtwSessionProfile.Outbound);

        Assert.Empty(results);
        Assert.Equal([contested], runtime.Attached);
        Assert.Empty(runtime.Stopped);
        Assert.Contains(contested, runtime.Active);
        Assert.Equal(1, runtime.GetCalls);
    }

    [Fact]
    public void EnumerationAttachmentStopAndPostcheckFailuresDoNotBroadenCleanupOrBlockCreation()
    {
        const string stale = "WinSight-Attribution-80";
        var runtime = new FakeRuntime(stale) { ThrowOnAttach = true };
        runtime.ThrowOnGetCalls.UnionWith([1, 3]);
        var lifecycle = new EtwSessionLifecycle(
            runtime,
            new FakeProcesses { States = { [80] = Sequence(EtwOwnerState.Absent, EtwOwnerState.Absent) } });

        lifecycle.Open(EtwSessionProfile.Attribution);

        // First enumeration fails before any targeted operation; creation is still attempted.
        Assert.Single(runtime.Created);
        Assert.Empty(runtime.Stopped);

        runtime.ThrowOnGetCalls.Clear();
        runtime.ThrowOnAttach = false;
        runtime.ThrowOnStop = true;
        lifecycle.Open(EtwSessionProfile.Attribution);

        Assert.Contains(stale, runtime.Attached);
        Assert.Empty(runtime.Stopped);
        lifecycle.Open(EtwSessionProfile.Attribution);
        Assert.Equal(3, runtime.Created.Count);
    }

    [Fact]
    public void AnAttachThatFindsNoLongerExistingSessionIsPreservedAndDoesNotBlockCreation()
    {
        const string stale = "WinSight-DNS-82";
        var runtime = new FakeRuntime(stale) { ReturnNullOnAttach = true };
        var lifecycle = new EtwSessionLifecycle(
            runtime,
            new FakeProcesses { States = { [82] = Sequence(EtwOwnerState.Absent, EtwOwnerState.Absent) } });

        lifecycle.Open(EtwSessionProfile.Dns);

        Assert.Equal([stale], runtime.Attached);
        Assert.Empty(runtime.Stopped);
        Assert.Single(runtime.Created);
    }

    [Fact]
    public void APostStopEnumerationFailureDoesNotPreventTheNextSessionFromBeingCreated()
    {
        const string stale = "WinSight-Attribution-81";
        var runtime = new FakeRuntime(stale);
        runtime.ThrowOnGetCalls.Add(2);
        var lifecycle = new EtwSessionLifecycle(
            runtime,
            new FakeProcesses { States = { [81] = Sequence(EtwOwnerState.Absent, EtwOwnerState.Absent) } });

        lifecycle.Open(EtwSessionProfile.Attribution);

        Assert.Equal([stale], runtime.Stopped);
        Assert.Single(runtime.Created);
    }

    [Fact]
    public void ANameThatRemainsAfterStopIsNotTreatedAsAReasonToTargetAnythingElse()
    {
        const string stale = "WinSight-Attribution-83";
        var runtime = new FakeRuntime(stale) { KeepActiveAfterStop = true };
        var lifecycle = new EtwSessionLifecycle(
            runtime,
            new FakeProcesses { States = { [83] = Sequence(EtwOwnerState.Absent, EtwOwnerState.Absent) } });

        var results = lifecycle.ReclaimProvenOrphans(EtwSessionProfile.Attribution);

        Assert.Equal([stale], runtime.Stopped);
        Assert.Contains(stale, runtime.Active);
        Assert.Equal([new EtwCleanupResult(stale, Disappeared: false)], results);
        Assert.Equal(2, runtime.GetCalls);
    }

    private sealed class FakeProcesses : IEtwProcessIdentity
    {
        public Dictionary<int, Queue<EtwOwnerState>> States { get; } = [];

        public int CurrentProcessId => CurrentPid;

        public string CurrentStartIdentity => CurrentStart;

        public EtwOwnerState Probe(int processId, string? expectedStartIdentity)
        {
            if (!States.TryGetValue(processId, out var states) || states.Count == 0)
            {
                return EtwOwnerState.Indeterminate;
            }

            var state = states.Dequeue();
            if (states.Count == 0)
            {
                states.Enqueue(state);
            }

            return state;
        }
    }

    private static Queue<EtwOwnerState> Sequence(params EtwOwnerState[] values) => new(values);

    private sealed class FakeRuntime(params string[] active) : IEtwSessionRuntime
    {
        private int _getCalls;

        public int GetCalls => _getCalls;

        public HashSet<string> Active { get; } = new(active, StringComparer.Ordinal);

        public List<string> Attached { get; } = [];

        public List<string> Stopped { get; } = [];

        public List<bool> StopArguments { get; } = [];

        public List<(string Name, TraceEventSessionOptions Options)> Created { get; } = [];

        public HashSet<int> ThrowOnGetCalls { get; } = [];

        public bool ThrowOnAttach { get; set; }

        public bool ThrowOnStop { get; set; }

        public bool ReturnNullOnAttach { get; set; }

        public bool KeepActiveAfterStop { get; set; }

        public IReadOnlyCollection<string> GetActiveSessionNames()
        {
            if (ThrowOnGetCalls.Contains(++_getCalls))
            {
                throw new InvalidOperationException("test enumeration failure");
            }

            return Active.ToArray();
        }

        public IEtwSessionHandle? Attach(string sessionName)
        {
            Attached.Add(sessionName);
            if (ThrowOnAttach)
            {
                throw new InvalidOperationException("test attach failure");
            }

            return !ReturnNullOnAttach && Active.Contains(sessionName) ? new FakeHandle(this, sessionName) : null;
        }

        public IEtwSessionHandle Create(string sessionName, TraceEventSessionOptions options)
        {
            Created.Add((sessionName, options));
            return new FakeHandle(this, sessionName);
        }

        private sealed class FakeHandle(FakeRuntime runtime, string name) : IEtwSessionHandle
        {
            public TraceEventSession? NativeSession => null;

            public void Stop(bool noThrow)
            {
                runtime.StopArguments.Add(noThrow);
                if (runtime.ThrowOnStop)
                {
                    throw new InvalidOperationException("test stop failure");
                }

                runtime.Stopped.Add(name);
                if (!runtime.KeepActiveAfterStop)
                {
                    runtime.Active.Remove(name);
                }
            }

            public void Dispose()
            {
            }
        }
    }
}
