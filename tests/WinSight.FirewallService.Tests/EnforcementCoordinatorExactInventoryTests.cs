using WinSight.Firewall;
using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

public sealed class EnforcementCoordinatorExactInventoryTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(), $"winsight-exact-inventory-{Guid.NewGuid():N}");

    [Theory]
    [InlineData("startup")]
    [InlineData("enable")]
    [InlineData("upsert")]
    public async Task DisabledBlockProducesZeroDesiredFilters(string transition)
    {
        var mode = transition == "enable" ? OutboundFirewallMode.AuditOnly : OutboundFirewallMode.Enforcement;
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(mode,
            transition == "upsert"
                ? []
                : [new AppFirewallPolicy(@"C:\apps\disabled.exe", OutboundAction.Block, Enabled: false)]));
        var reconciler = new InventoryReconciler();
        await using var coordinator = new EnforcementCoordinator(
            store, reconciler, new RecordingStartModeController());

        switch (transition)
        {
            case "startup":
                await coordinator.ApplyBlocksAsync();
                break;
            case "enable":
                await coordinator.EnableEnforcementAsync();
                break;
            default:
                await coordinator.UpsertPolicyAsync(
                    new AppFirewallPolicy(@"C:\apps\disabled.exe", OutboundAction.Block, Enabled: false));
                break;
        }

        Assert.Empty(reconciler.Inventory);
        Assert.All(reconciler.DesiredSnapshots, Assert.Empty);
    }

    [Fact]
    public async Task StartupReconcileReplacesPreexistingExtraAndOrphanInventory()
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.Enforcement,
            [new AppFirewallPolicy(@"C:\apps\wanted.exe", OutboundAction.Block)]));
        var reconciler = new InventoryReconciler(
            @"C:\apps\wanted.exe:wrong-shape",
            @"C:\apps\extra.exe",
            "orphan-provider-filter");
        await using var coordinator = new EnforcementCoordinator(
            store, reconciler, new RecordingStartModeController());

        await coordinator.ApplyBlocksAsync();

        Assert.Equal([@"C:\apps\wanted.exe"], reconciler.Inventory);
        Assert.True(reconciler.VerifyCalls >= 1);
        Assert.Equal(FirewallEnforcementState.Active, coordinator.EffectiveState);
    }

    [Theory]
    [InlineData("missing-v4")]
    [InlineData("missing-v6")]
    [InlineData("missing-provider")]
    [InlineData("missing-sublayer")]
    [InlineData("wrong-shape")]
    [InlineData("extra-filter")]
    [InlineData("enumeration-error")]
    public async Task RuntimeVerificationFailureAlwaysPublishesDegraded(string failure)
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.AuditOnly,
            [new AppFirewallPolicy(@"C:\apps\blocked.exe", OutboundAction.Block)]));
        var reconciler = new InventoryReconciler();
        reconciler.Verification.Enqueue(true);
        if (failure == "enumeration-error")
            reconciler.Verification.Enqueue(new IOException("synthetic inventory read failure"));
        else
            reconciler.Verification.Enqueue(false);
        await using var coordinator = new EnforcementCoordinator(
            store, reconciler, new RecordingStartModeController());
        await coordinator.EnableEnforcementAsync();

        var status = await coordinator.GetRuntimeStatusAsync();

        Assert.Equal(OutboundFirewallMode.Enforcement, status.Mode);
        Assert.Equal(FirewallEnforcementState.Degraded, status.EffectiveState);
        Assert.False(status.EnforcementEnabled);
    }

    [Fact]
    public async Task UpsertPersistenceRollbackRestoresExactOriginalWithoutOrphans()
    {
        var path = Path.Combine(_directory, "rollback-policies.json");
        var seed = new FirewallPolicyStore(path, allowEnforcement: true);
        await seed.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.Enforcement,
            [new AppFirewallPolicy(@"C:\apps\original.exe", OutboundAction.Block)]));
        var guarded = new FirewallPolicyStore(path, allowEnforcement: true,
            storageTrustGuard: new FailSecondInspectGuard());
        var reconciler = new InventoryReconciler(
            @"C:\apps\original.exe", "orphan-filter");
        await using var coordinator = new EnforcementCoordinator(
            guarded, reconciler, new RecordingStartModeController());

        var error = await Assert.ThrowsAsync<FirewallTransitionException>(() =>
            coordinator.UpsertPolicyAsync(
                new AppFirewallPolicy(@"C:\apps\new.exe", OutboundAction.Block)));

        Assert.Equal("UpsertPersistenceFailed", error.Code);
        Assert.Equal([@"C:\apps\original.exe"], reconciler.Inventory);
        Assert.Equal(2, reconciler.ReconcileCalls);
        Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);
    }

    [Fact]
    public async Task FailedEnableCleansPartialExactInventoryAndPersistsAuditOnly()
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.AuditOnly,
            [new AppFirewallPolicy(@"C:\apps\one.exe", OutboundAction.Block)]));
        var reconciler = new InventoryReconciler("orphan-filter") { FailReconcileCall = 1 };
        await using var coordinator = new EnforcementCoordinator(
            store, reconciler, new RecordingStartModeController());

        await Assert.ThrowsAsync<FirewallTransitionException>(() => coordinator.EnableEnforcementAsync());

        Assert.Empty(reconciler.Inventory);
        Assert.Equal(1, reconciler.CleanupCalls);
        Assert.Equal(OutboundFirewallMode.AuditOnly, (await store.LoadAsync()).Mode);
    }

    [Fact]
    public async Task AuditOnlyStartupAndEmergencyDisableRemoveEveryOwnedOrphan()
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.AuditOnly, []));
        var startup = new InventoryReconciler("orphan-v4", "orphan-v6", "orphan-container");
        await using (var coordinator = new EnforcementCoordinator(
            store, startup, new RecordingStartModeController()))
        {
            await coordinator.ApplyBlocksAsync();
            Assert.Empty(startup.Inventory);
        }

        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.Enforcement, []));
        var emergency = new InventoryReconciler("orphan-v4", "orphan-v6", "orphan-container");
        await using (var coordinator = new EnforcementCoordinator(
            store, emergency, new RecordingStartModeController()))
        {
            await coordinator.EmergencyDisableAsync();
            Assert.Empty(emergency.Inventory);
            Assert.Equal(1, emergency.CleanupCalls);
        }
    }

    private FirewallPolicyStore Store() => new(
        Path.Combine(_directory, "policies.json"), allowEnforcement: true);

    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
    }

    private sealed class InventoryReconciler(params string[] initial) : IWinSightWfpReconciler
    {
        public HashSet<string> Inventory { get; } = new(initial, StringComparer.OrdinalIgnoreCase);
        public List<IReadOnlyList<string>> DesiredSnapshots { get; } = [];
        public Queue<object> Verification { get; } = new();
        public int ReconcileCalls { get; private set; }
        public int VerifyCalls { get; private set; }
        public int CleanupCalls { get; private set; }
        public int? FailReconcileCall { get; init; }
        public bool IsSupported => true;

        public Task ReconcileExactAsync(
            IReadOnlyList<AppFirewallPolicy> policies,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var desired = policies
                .Where(policy => policy.Enabled && policy.Action == OutboundAction.Block)
                .Select(policy => policy.ExecutablePath)
                .ToArray();
            DesiredSnapshots.Add(desired);
            Inventory.Clear();
            Inventory.UnionWith(desired);
            if (++ReconcileCalls == FailReconcileCall)
                throw new IOException("synthetic partial reconciliation failure");
            return Task.CompletedTask;
        }

        public Task<bool> VerifyExactAsync(
            IReadOnlyList<AppFirewallPolicy> policies,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            VerifyCalls++;
            if (Verification.TryDequeue(out var result))
            {
                if (result is Exception error) throw error;
                return Task.FromResult((bool)result);
            }
            var desired = policies
                .Where(policy => policy.Enabled && policy.Action == OutboundAction.Block)
                .Select(policy => policy.ExecutablePath)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            return Task.FromResult(Inventory.SetEquals(desired));
        }

        public Task CleanupAllAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CleanupCalls++;
            Inventory.Clear();
            return Task.CompletedTask;
        }
    }

    private sealed class FailSecondInspectGuard : IFirewallStorageTrustGuard
    {
        private int _inspections;
        public FirewallStorageTrustLease Inspect() => Interlocked.Increment(ref _inspections) == 1
            ? new(true, "Trusted", new object())
            : new(false, "SyntheticSaveFailure");
        public FirewallStorageTrustLease Revalidate(FirewallStorageTrustLease lease) => lease;
    }
}
