using WinSight.Firewall;
using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

/// <summary>
/// Regression tests for the read-side of the enforcement transition. A durable mode and a
/// runtime state are meaningful only as a pair: publishing one from before a transition and the
/// other from after it can make the dashboard report protection that never existed.
/// </summary>
public sealed class EnforcementCoordinatorStatusTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "winsight-status-tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task GetRuntimeStatusAsync_DuringEnable_WaitsForAndReturnsOneCoherentSnapshot()
    {
        var store = new FirewallPolicyStore(Path.Combine(_directory, "policies.json"), allowEnforcement: true);
        await store.SaveAsync(new OutboundFirewallConfiguration(
            OutboundFirewallMode.AuditOnly,
            [new AppFirewallPolicy(@"C:\apps\blocked.exe", OutboundAction.Block)]));
        var engine = new BlockingApplyEngine();
        await using var coordinator = TestEnforcementCoordinator.Create(store, engine);

        var enable = coordinator.EnableEnforcementAsync();
        await engine.ApplyStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var status = coordinator.GetRuntimeStatusAsync();

        // The read must share the mutation lock. Returning here would allow an impossible pair
        // such as persisted Enforcement with pre-transition AuditOnly, or the reverse.
        Assert.False(status.IsCompleted);

        engine.ReleaseApply.TrySetResult();
        await enable;
        var snapshot = await status;

        Assert.Equal(OutboundFirewallMode.Enforcement, snapshot.Mode);
        Assert.Equal(FirewallEnforcementState.Active, snapshot.EffectiveState);
        Assert.True(snapshot.EnforcementEnabled);
    }

    [Theory]
    [InlineData(false, "EnableApplyFailed", OutboundFirewallMode.AuditOnly)]
    [InlineData(true, "EnableRollbackFailed", OutboundFirewallMode.AuditOnly)]
    public async Task GetRuntimeStatusAsync_DuringFailedEnable_NeverPublishesStaleAuditOnly(
        bool rollbackFails,
        string expectedCode,
        OutboundFirewallMode expectedMode)
    {
        var store = new FirewallPolicyStore(Path.Combine(_directory, "policies.json"), allowEnforcement: true);
        await store.SaveAsync(new OutboundFirewallConfiguration(
            OutboundFirewallMode.AuditOnly,
            [new AppFirewallPolicy(@"C:\apps\blocked.exe", OutboundAction.Block)]));
        var engine = new BlockingEnableFailureEngine(rollbackFails);
        await using var coordinator = TestEnforcementCoordinator.Create(store, engine);

        var enable = coordinator.EnableEnforcementAsync();
        await engine.ApplyStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var status = coordinator.GetRuntimeStatusAsync();

        Assert.False(status.IsCompleted);

        engine.ReleaseApply.TrySetResult();
        var snapshot = await status.WaitAsync(TimeSpan.FromSeconds(5));
        var failure = await Assert.ThrowsAsync<FirewallTransitionException>(() => enable);

        Assert.Equal(expectedCode, failure.Code);
        Assert.Equal(expectedMode, snapshot.Mode);
        Assert.Equal(FirewallEnforcementState.Degraded, snapshot.EffectiveState);
        Assert.False(snapshot.EnforcementEnabled);
    }

    [Theory]
    [InlineData(false, "EmergencyCleanupFailed")]
    [InlineData(true, "EmergencyCleanupRollbackFailed")]
    public async Task GetRuntimeStatusAsync_DuringFailedEmergencyDisable_NeverPublishesStaleActive(
        bool restoreFails,
        string expectedCode)
    {
        var store = new FirewallPolicyStore(Path.Combine(_directory, "policies.json"), allowEnforcement: true);
        await store.SaveAsync(new OutboundFirewallConfiguration(
            OutboundFirewallMode.AuditOnly,
            [new AppFirewallPolicy(@"C:\apps\blocked.exe", OutboundAction.Block)]));
        var engine = new BlockingEmergencyFailureEngine(restoreFails);
        await using var coordinator = TestEnforcementCoordinator.Create(store, engine);
        await coordinator.EnableEnforcementAsync();
        Assert.Equal(FirewallEnforcementState.Active, coordinator.EffectiveState);

        var emergency = coordinator.EmergencyDisableAsync();
        await engine.CleanupStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var status = coordinator.GetRuntimeStatusAsync();

        Assert.False(status.IsCompleted);

        engine.ReleaseCleanup.TrySetResult();
        var snapshot = await status.WaitAsync(TimeSpan.FromSeconds(5));
        var failure = await Assert.ThrowsAsync<FirewallTransitionException>(() => emergency);

        Assert.Equal(expectedCode, failure.Code);
        Assert.Equal(OutboundFirewallMode.Enforcement, snapshot.Mode);
        Assert.Equal(FirewallEnforcementState.Degraded, snapshot.EffectiveState);
        Assert.False(snapshot.EnforcementEnabled);
    }

    [Fact]
    public async Task GetRuntimeStatusAsync_DuringDemandStartFailure_WaitsThenReportsAuditOnlyDegraded()
    {
        var store = new FirewallPolicyStore(Path.Combine(_directory, "policies.json"), allowEnforcement: true);
        await store.SaveAsync(new OutboundFirewallConfiguration(
            OutboundFirewallMode.AuditOnly,
            [new AppFirewallPolicy(@"C:\apps\blocked.exe", OutboundAction.Block)]));
        var startMode = new BlockingDemandFailureStartMode();
        var reloadedStore = new FirewallPolicyStore(
            Path.Combine(_directory, "policies.json"), allowEnforcement: true);
        await using var coordinator = TestEnforcementCoordinator.Create(
            reloadedStore, new CleanupEngine(), startMode);
        await coordinator.EnableEnforcementAsync();

        var emergency = coordinator.EmergencyDisableAsync();
        await startMode.DemandStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var status = coordinator.GetRuntimeStatusAsync();
        Assert.False(status.IsCompleted);

        startMode.ReleaseDemand.TrySetResult();
        await Assert.ThrowsAsync<IOException>(() => emergency);
        var snapshot = await status.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(OutboundFirewallMode.AuditOnly, snapshot.Mode);
        Assert.Equal(FirewallEnforcementState.Degraded, snapshot.EffectiveState);
        Assert.False(snapshot.EnforcementEnabled);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private sealed class BlockingApplyEngine : IOutboundFirewallEngine
    {
        public TaskCompletionSource ApplyStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseApply { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool IsSupported => true;

        public async Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        {
            ApplyStarted.TrySetResult();
            await ReleaseApply.Task.WaitAsync(cancellationToken);
        }

        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class BlockingEnableFailureEngine(bool rollbackFails) : IOutboundFirewallEngine
    {
        public TaskCompletionSource ApplyStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseApply { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool IsSupported => true;

        public async Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        {
            ApplyStarted.TrySetResult();
            await ReleaseApply.Task.WaitAsync(cancellationToken);
            throw new IOException("synthetic apply failure");
        }

        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default) =>
            rollbackFails
                ? Task.FromException(new IOException("synthetic rollback failure"))
                : Task.CompletedTask;
    }

    private sealed class BlockingEmergencyFailureEngine(bool restoreFails) :
        IOutboundFirewallEngine,
        ITestWinSightFirewallCleanup
    {
        private bool _cleanupFailed;

        public TaskCompletionSource CleanupStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseCleanup { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool IsSupported => true;

        public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default) =>
            _cleanupFailed && restoreFails
                ? Task.FromException(new IOException("synthetic restore failure"))
                : Task.CompletedTask;

        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default) => Task.CompletedTask;

        public async Task CleanupWinSightAsync(
            IReadOnlyList<AppFirewallPolicy> knownPolicies,
            CancellationToken cancellationToken = default)
        {
            CleanupStarted.TrySetResult();
            await ReleaseCleanup.Task.WaitAsync(cancellationToken);
            _cleanupFailed = true;
            throw new IOException("synthetic cleanup failure");
        }
    }

    private sealed class CleanupEngine : IOutboundFirewallEngine, ITestWinSightFirewallCleanup
    {
        public bool IsSupported => true;
        public Task CleanupWinSightAsync(IReadOnlyList<AppFirewallPolicy> knownPolicies,
            CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class BlockingDemandFailureStartMode : IFirewallServiceStartModeController
    {
        public TaskCompletionSource DemandStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseDemand { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void SetAutomatic() { }

        public void SetDemandStart()
        {
            DemandStarted.TrySetResult();
            ReleaseDemand.Task.GetAwaiter().GetResult();
            throw new IOException("synthetic SCM demand-start failure");
        }
    }
}
