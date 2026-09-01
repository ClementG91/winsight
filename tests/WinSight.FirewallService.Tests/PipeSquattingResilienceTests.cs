using Microsoft.Extensions.Logging.Abstractions;

using WinSight.Firewall;
using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

/// <summary>
/// No filter may be installed until the command endpoint is proven live.
/// </summary>
/// <remarks>
/// <b>The attack.</b> The pipe name is fixed and public, and the first instance is created with
/// <c>FIRST_PIPE_INSTANCE</c>. An unprivileged interactive user who creates that name first makes
/// the listener fail. With the startup service registered ahead of the pipe worker, the WFP filters
/// were already installed by then - and because the session is dynamic, BFE destroyed them when the
/// host stopped. The squatter therefore obtained a loop of "filters applied, then immediately
/// removed", which is worse than never arming: for each interval the machine believed it was
/// protected and was not.
///
/// Waiting on readiness inverts that. If the endpoint never comes up, nothing is installed, and the
/// machine is honestly unfiltered instead of intermittently filtered.
/// </remarks>
public sealed class PipeSquattingResilienceTests
{
    [Fact]
    public async Task NoFilterIsInstalledWhenTheEndpointNeverComesUp()
    {
        using var coordinator = new CountingCoordinator();
        var service = new EnforcementStartupService(
            coordinator.Coordinator,
            NullLogger<EnforcementStartupService>.Instance,
            new NeverReady());

        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await service.StartAsync(cancellation.Token);

        Assert.Equal(0, coordinator.Applied);
    }

    [Fact]
    public async Task FiltersAreAppliedOnceTheEndpointIsListening()
    {
        using var coordinator = new CountingCoordinator();
        var service = new EnforcementStartupService(
            coordinator.Coordinator,
            NullLogger<EnforcementStartupService>.Instance,
            new AlreadyReady());

        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await service.StartAsync(cancellation.Token);

        Assert.Equal(1, coordinator.Applied);
    }

    /// <summary>A listener that exposes no readiness signal must behave exactly as before.</summary>
    [Fact]
    public async Task AListenerWithoutAReadinessSignalStillArms()
    {
        using var coordinator = new CountingCoordinator();
        var service = new EnforcementStartupService(
            coordinator.Coordinator, NullLogger<EnforcementStartupService>.Instance, readiness: null);

        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await service.StartAsync(cancellation.Token);

        Assert.Equal(1, coordinator.Applied);
    }

    /// <summary>
    /// A listener that faults before announcing readiness must not have filters installed on the way
    /// out - that is the exact sequence the squat produces.
    /// </summary>
    [Fact]
    public async Task AFaultedListenerInstallsNothing()
    {
        using var coordinator = new CountingCoordinator();
        var service = new EnforcementStartupService(
            coordinator.Coordinator,
            NullLogger<EnforcementStartupService>.Instance,
            new FaultedReadiness());

        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await service.StartAsync(cancellation.Token);

        Assert.Equal(0, coordinator.Applied);
    }

    /// <summary>
    /// A coordinator over a temporary audit-only store, wired to a reconciler that only counts.
    /// Calling ApplyBlocksAsync in audit-only mode reaches CleanupAllAsync, so a non-zero count is
    /// proof the startup service decided to touch WFP at all - which is the thing under test.
    /// </summary>
    private sealed class CountingCoordinator : IDisposable
    {
        private readonly string _directory =
            Path.Combine(Path.GetTempPath(), $"winsight-squat-{Guid.NewGuid():N}");
        private readonly CountingReconciler _reconciler = new();

        internal CountingCoordinator()
        {
            Directory.CreateDirectory(_directory);
            var store = new FirewallPolicyStore(
                Path.Combine(_directory, "policies.json"), storageTrust: () => (true, string.Empty));
            Coordinator = new EnforcementCoordinator(
                store, () => _reconciler, new NoOpStartMode());
        }

        internal EnforcementCoordinator Coordinator { get; }

        internal int Applied => _reconciler.Calls;

        public void Dispose()
        {
            try { Directory.Delete(_directory, recursive: true); }
            catch (IOException) { }
        }
    }

    private sealed class CountingReconciler : IWinSightWfpReconciler
    {
        private int _calls;

        internal int Calls => Volatile.Read(ref _calls);

        public bool IsSupported => true;

        public Task ReconcileExactAsync(
            IReadOnlyList<AppFirewallPolicy> policies, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _calls);
            return Task.CompletedTask;
        }

        public Task<bool> VerifyExactAsync(
            IReadOnlyList<AppFirewallPolicy> policies, CancellationToken cancellationToken = default) =>
            Task.FromResult(true);

        public Task CleanupAllAsync(CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _calls);
            return Task.CompletedTask;
        }
    }

    private sealed class NoOpStartMode : IFirewallServiceStartModeController
    {
        public void SetAutomatic()
        {
        }

        public void SetDemandStart()
        {
        }
    }

    private sealed class NeverReady : IFirewallServiceReadiness
    {
        public Task Ready { get; } = new TaskCompletionSource().Task;
    }

    private sealed class AlreadyReady : IFirewallServiceReadiness
    {
        public Task Ready { get; } = Task.CompletedTask;
    }

    private sealed class FaultedReadiness : IFirewallServiceReadiness
    {
        public Task Ready { get; } =
            Task.FromException(new InvalidOperationException("the pipe name was already taken"));
    }
}
