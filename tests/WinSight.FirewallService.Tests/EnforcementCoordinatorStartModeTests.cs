using System.ComponentModel;
using WinSight.Firewall;
using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

public sealed class EnforcementCoordinatorStartModeTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(), $"winsight-start-mode-{Guid.NewGuid():N}");

    [Fact]
    public async Task Enable_SetsAutomaticBeforePersistenceAndWfp()
    {
        var store = Store();
        await SeedAsync(store, OutboundFirewallMode.AuditOnly);
        var events = new List<string>();
        var startMode = new RecordingStartModeController(onAutomatic: () =>
        {
            events.Add("automatic");
            Assert.Equal(OutboundFirewallMode.AuditOnly, store.LoadAsync().GetAwaiter().GetResult().Mode);
        });
        var engine = new CallbackEngine(onApply: async () =>
        {
            events.Add("apply");
            Assert.Equal(OutboundFirewallMode.Enforcement, (await store.LoadAsync()).Mode);
        });
        await using var coordinator = TestEnforcementCoordinator.Create(store, engine, startMode);

        await coordinator.EnableEnforcementAsync();

        Assert.Equal(["automatic", "apply"], events);
        Assert.DoesNotContain("demand", startMode.Events);
        Assert.Equal(FirewallEnforcementState.Active, coordinator.EffectiveState);
    }

    [Fact]
    public async Task Enable_AutomaticFailureRollsBackOwnedInventoryAndDemandStart()
    {
        var store = Store();
        await SeedAsync(store, OutboundFirewallMode.AuditOnly);
        var engine = new RecordingEngine();
        var startMode = new RecordingStartModeController
        {
            AutomaticFailure = new Win32Exception(5),
        };
        await using var coordinator = TestEnforcementCoordinator.Create(store, engine, startMode);

        var exception = await Assert.ThrowsAsync<FirewallTransitionException>(
            () => coordinator.EnableEnforcementAsync());

        Assert.Equal("EnableStartModeFailed", exception.Code);
        Assert.IsType<Win32Exception>(exception.InnerException);
        Assert.Equal(["automatic", "demand"], startMode.Events);
        Assert.Empty(engine.Events);
        Assert.Equal(OutboundFirewallMode.AuditOnly, (await store.LoadAsync()).Mode);
        Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);
    }

    [Fact]
    public async Task Enable_ApplyFailureRollsBackFiltersThenAuditOnlyThenDemandStart()
    {
        var store = Store();
        await SeedAsync(store, OutboundFirewallMode.AuditOnly, twoPolicies: true);
        var events = new List<string>();
        var engine = new FailingSecondApplyEngine(events);
        var startMode = new RecordingStartModeController(
            onAutomatic: () => events.Add("automatic"),
            onDemandStart: () =>
            {
                events.Add("demand");
                Assert.Equal(OutboundFirewallMode.AuditOnly, store.LoadAsync().GetAwaiter().GetResult().Mode);
            });
        await using var coordinator = TestEnforcementCoordinator.Create(store, engine, startMode);

        var exception = await Assert.ThrowsAsync<FirewallTransitionException>(
            () => coordinator.EnableEnforcementAsync());

        Assert.Equal("EnableApplyFailed", exception.Code);
        Assert.Equal(
            ["automatic", "apply:one.exe", "apply:two.exe", "remove:two.exe", "remove:one.exe", "demand"],
            events);
        Assert.Equal(OutboundFirewallMode.AuditOnly, (await store.LoadAsync()).Mode);
        Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);
    }

    [Fact]
    public async Task Enable_PersistenceFailureRestoresAuditOnlyAndDemandStartWithoutWfp()
    {
        var path = Path.Combine(_directory, "policies.json");
        var seed = new FirewallPolicyStore(path, allowEnforcement: true);
        await SeedAsync(seed, OutboundFirewallMode.AuditOnly);
        var store = new FirewallPolicyStore(path, allowEnforcement: true,
            storageTrustGuard: new FailOnlySecondInspectGuard());
        var engine = new RecordingEngine();
        var startMode = new RecordingStartModeController(onDemandStart: () =>
            Assert.Equal(OutboundFirewallMode.AuditOnly, seed.LoadAsync().GetAwaiter().GetResult().Mode));
        await using var coordinator = TestEnforcementCoordinator.Create(store, engine, startMode);

        var exception = await Assert.ThrowsAsync<FirewallTransitionException>(
            () => coordinator.EnableEnforcementAsync());

        Assert.Equal("EnablePersistenceFailed", exception.Code);
        Assert.Equal(["automatic", "demand"], startMode.Events);
        Assert.Empty(engine.Events);
        Assert.Equal(OutboundFirewallMode.AuditOnly, (await seed.LoadAsync()).Mode);
        Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);
    }

    [Fact]
    public async Task Enable_DemandStartRollbackFailureIsDegradedAndAuditOnly()
    {
        var store = Store();
        await SeedAsync(store, OutboundFirewallMode.AuditOnly, twoPolicies: true);
        var startMode = new RecordingStartModeController
        {
            DemandStartFailure = new Win32Exception(5),
        };
        await using var coordinator = TestEnforcementCoordinator.Create(
            store, new FailingSecondApplyEngine([]), startMode);

        var exception = await Assert.ThrowsAsync<FirewallTransitionException>(
            () => coordinator.EnableEnforcementAsync());

        Assert.Equal("EnableRollbackFailed", exception.Code);
        Assert.Equal(["automatic", "demand"], startMode.Events);
        Assert.Equal(OutboundFirewallMode.AuditOnly, (await store.LoadAsync()).Mode);
        Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);
    }

    [Fact]
    public async Task Startup_AutomaticFailureCleansOwnedInventoryAndFallsBackAuditOnly()
    {
        var store = Store();
        await SeedAsync(store, OutboundFirewallMode.Enforcement);
        var engine = new RecordingEngine();
        var startMode = new RecordingStartModeController
        {
            AutomaticFailure = new Win32Exception(5),
        };
        await using var coordinator = TestEnforcementCoordinator.Create(store, engine, startMode);

        var exception = await Assert.ThrowsAsync<FirewallTransitionException>(
            () => coordinator.ApplyBlocksAsync());

        Assert.Equal("StartupApplyFailed", exception.Code);
        Assert.IsType<Win32Exception>(exception.InnerException);
        Assert.Equal(["remove"], engine.Events);
        Assert.Equal(OutboundFirewallMode.AuditOnly, (await store.LoadAsync()).Mode);
        Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);
    }

    [Fact]
    public async Task Startup_SetsAutomaticBeforeWfpAndPublishesActiveOnlyAfterApply()
    {
        var store = Store();
        await SeedAsync(store, OutboundFirewallMode.Enforcement);
        var events = new List<string>();
        var startMode = new RecordingStartModeController(onAutomatic: () => events.Add("automatic"));
        var engine = new CallbackEngine(onApply: () =>
        {
            events.Add("apply");
            return Task.CompletedTask;
        });
        await using var coordinator = TestEnforcementCoordinator.Create(store, engine, startMode);

        await coordinator.ApplyBlocksAsync();

        Assert.Equal(["automatic", "apply"], events);
        Assert.Equal(FirewallEnforcementState.Active, coordinator.EffectiveState);
    }

    [Fact]
    public async Task Emergency_CleansThenPersistsAuditOnlyThenSetsDemandStart()
    {
        var store = Store();
        await SeedAsync(store, OutboundFirewallMode.Enforcement);
        var events = new List<string>();
        var engine = new CallbackCleanupEngine(() => events.Add("cleanup"));
        var startMode = new RecordingStartModeController(onDemandStart: () =>
        {
            events.Add("demand");
            Assert.Equal(OutboundFirewallMode.AuditOnly, store.LoadAsync().GetAwaiter().GetResult().Mode);
        });
        await using var coordinator = TestEnforcementCoordinator.Create(store, engine, startMode);

        await coordinator.EmergencyDisableAsync();

        Assert.Equal(["cleanup", "demand"], events);
        Assert.Equal(FirewallEnforcementState.AuditOnly, coordinator.EffectiveState);
    }

    [Fact]
    public async Task Emergency_DemandStartFailureKeepsFiltersOffAndAuditOnlyDurable()
    {
        var store = Store();
        await SeedAsync(store, OutboundFirewallMode.Enforcement);
        var engine = new CleanupRecordingEngine();
        var startMode = new RecordingStartModeController
        {
            DemandStartFailure = new Win32Exception(5),
        };
        await using var coordinator = TestEnforcementCoordinator.Create(store, engine, startMode);

        await Assert.ThrowsAsync<Win32Exception>(() => coordinator.EmergencyDisableAsync());

        Assert.Equal(["cleanup"], engine.Events);
        Assert.Equal(["demand"], startMode.Events);
        Assert.Equal(OutboundFirewallMode.AuditOnly, (await store.LoadAsync()).Mode);
        Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);
    }

    private FirewallPolicyStore Store() =>
        new(Path.Combine(_directory, "policies.json"), allowEnforcement: true);

    private static Task SeedAsync(
        FirewallPolicyStore store,
        OutboundFirewallMode mode,
        bool twoPolicies = false) =>
        store.SaveAsync(new OutboundFirewallConfiguration(mode,
            twoPolicies
                ?
                [
                    new AppFirewallPolicy(@"C:\apps\one.exe", OutboundAction.Block),
                    new AppFirewallPolicy(@"C:\apps\two.exe", OutboundAction.Block),
                ]
                : [new AppFirewallPolicy(@"C:\apps\one.exe", OutboundAction.Block)]));

    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
    }

    private sealed class RecordingEngine : IOutboundFirewallEngine
    {
        public List<string> Events { get; } = [];
        public bool IsSupported => true;
        public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        { Events.Add("apply"); return Task.CompletedTask; }
        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default)
        { Events.Add("remove"); return Task.CompletedTask; }
    }

    private sealed class CallbackEngine(Func<Task> onApply) : IOutboundFirewallEngine
    {
        public bool IsSupported => true;
        public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default) => onApply();
        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class FailingSecondApplyEngine(List<string> events) : IOutboundFirewallEngine
    {
        private int _applies;
        public bool IsSupported => true;
        public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        {
            events.Add($"apply:{Path.GetFileName(policy.ExecutablePath)}");
            if (++_applies == 2) throw new IOException("synthetic apply failure");
            return Task.CompletedTask;
        }
        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default)
        { events.Add($"remove:{Path.GetFileName(executablePath)}"); return Task.CompletedTask; }
    }

    private sealed class CleanupRecordingEngine : IOutboundFirewallEngine, ITestWinSightFirewallCleanup
    {
        public List<string> Events { get; } = [];
        public bool IsSupported => true;
        public Task CleanupWinSightAsync(IReadOnlyList<AppFirewallPolicy> knownPolicies,
            CancellationToken cancellationToken = default)
        { Events.Add("cleanup"); return Task.CompletedTask; }
        public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        { Events.Add("apply"); return Task.CompletedTask; }
        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default)
        { Events.Add("remove"); return Task.CompletedTask; }
    }

    private sealed class CallbackCleanupEngine(Action onCleanup) : IOutboundFirewallEngine, ITestWinSightFirewallCleanup
    {
        public bool IsSupported => true;
        public Task CleanupWinSightAsync(IReadOnlyList<AppFirewallPolicy> knownPolicies,
            CancellationToken cancellationToken = default)
        { onCleanup(); return Task.CompletedTask; }
        public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class FailOnlySecondInspectGuard : IFirewallStorageTrustGuard
    {
        private int _inspections;
        public FirewallStorageTrustLease Inspect() => Interlocked.Increment(ref _inspections) == 2
            ? new(false, "SyntheticSaveFailure")
            : new(true, "Trusted", new object());
        public FirewallStorageTrustLease Revalidate(FirewallStorageTrustLease lease) => lease;
    }
}
