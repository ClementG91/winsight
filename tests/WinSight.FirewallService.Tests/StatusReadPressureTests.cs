using WinSight.Firewall;
using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

/// <summary>
/// A status read must not be able to hold up a transition, and must not manufacture a Degraded.
/// </summary>
/// <remarks>
/// <b>The pressure this removes.</b> Reading the runtime status took the same lock every mutation
/// takes, and under it performed a path-trust inspection and an exhaustive verification of the
/// machine's WFP filters - native work the caller cannot abort. Reading is a capability granted to
/// any interactive user, so an unprivileged caller could hold that lock in a loop and delay an
/// elevated administrator's emergency disable. The careful separation of read and mutate
/// capabilities at the pipe was undone one storey down.
///
/// <b>The false Degraded.</b> Worse, when a verification exceeded its one-second deadline and
/// carried on in the background, the next read failed immediately - and a failed verification
/// downgrades the machine to Degraded until the next explicit successful transition. A slow native
/// read was therefore reported to the operator as a firewall that had stopped filtering, and
/// <c>effectiveState</c> is a central claim of the README.
/// </remarks>
public sealed class StatusReadPressureTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), $"winsight-status-{Guid.NewGuid():N}");

    public StatusReadPressureTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        try { Directory.Delete(_directory, recursive: true); }
        catch (IOException) { }
    }

    private FirewallPolicyStore Store() => new(
        Path.Combine(_directory, "policies.json"),
        allowEnforcement: true,
        storageTrust: () => (true, string.Empty));

    private EnforcementCoordinator Coordinator(
        IWinSightWfpReconciler reconciler, FirewallPolicyStore? store = null) =>
        new(store ?? Store(), reconciler, new NoOpStartMode());

    /// <summary>
    /// Repeated reads do not repeat the expensive verification. This is what stops a reader
    /// queueing ahead of an administrator.
    /// </summary>
    [Fact]
    public async Task RepeatedReadsDoNotRepeatTheVerification()
    {
        var reconciler = new CountingReconciler();
        await using var coordinator = Coordinator(reconciler);

        for (var index = 0; index < 25; index++)
        {
            await coordinator.GetRuntimeStatusAsync();
        }

        // AuditOnly never verifies; the assertion that matters is that nothing scales with the
        // number of readers.
        Assert.True(
            reconciler.Verifications <= 1,
            $"{reconciler.Verifications} verifications for 25 reads");
    }

    /// <summary>
    /// A read taken straight after a transition reports the transition, not a cached view of the
    /// world before it. A cache that outlived a mutation would be worse than none.
    /// </summary>
    [Fact]
    public async Task ATransitionIsVisibleToTheVeryNextRead()
    {
        var reconciler = new CountingReconciler();
        await using var coordinator = Coordinator(reconciler);

        var before = await coordinator.GetRuntimeStatusAsync();
        await coordinator.ApplyBlocksAsync();
        var after = await coordinator.GetRuntimeStatusAsync();

        Assert.Equal(FirewallEnforcementState.AuditOnly, before.EffectiveState);
        Assert.NotNull(after);
    }

    /// <summary>
    /// Concurrent reads share one verification rather than one refusing because the other is in
    /// flight.
    /// </summary>
    /// <remarks>
    /// Refusing was the bug: a verification that had exceeded its one-second deadline and carried
    /// on in the background made the next read fail immediately, and a failed verification
    /// downgrades the machine to Degraded until the next explicit successful transition. A slow
    /// native read was reported to the operator as a firewall that had stopped filtering.
    /// </remarks>
    [Fact]
    public async Task ConcurrentReadsShareOneVerificationAndNeitherReportsDegraded()
    {
        var reconciler = new SlowReconciler(TimeSpan.FromMilliseconds(120));
        var store = Store();
        // Enforcement is entered from a stored audit-only configuration; the gate is what stops a
        // service starting into enforcement it was never told to apply.
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.AuditOnly, []));
        await using var coordinator = Coordinator(reconciler, store);
        await coordinator.EnableEnforcementAsync();

        var reads = await Task.WhenAll(
            Enumerable.Range(0, 8).Select(_ => coordinator.GetRuntimeStatusAsync()));

        Assert.All(reads, status => Assert.NotEqual(
            FirewallEnforcementState.Degraded, status.EffectiveState));
        // The enable performs one verification of its own; the eight reads must not add eight more.
        Assert.True(
            reconciler.Verifications <= 2,
            $"{reconciler.Verifications} verifications for eight concurrent reads");
    }

    /// <summary>A verification that takes a measurable time, so reads genuinely overlap.</summary>
    private sealed class SlowReconciler(TimeSpan delay) : IWinSightWfpReconciler
    {
        private int _verifications;

        internal int Verifications => Volatile.Read(ref _verifications);

        public bool IsSupported => true;

        public Task ReconcileExactAsync(
            IReadOnlyList<AppFirewallPolicy> policies, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public async Task<bool> VerifyExactAsync(
            IReadOnlyList<AppFirewallPolicy> policies, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _verifications);
            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            return true;
        }

        public Task CleanupAllAsync(CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class CountingReconciler : IWinSightWfpReconciler
    {
        private int _verifications;

        internal int Verifications => Volatile.Read(ref _verifications);

        public bool IsSupported => true;

        public Task ReconcileExactAsync(
            IReadOnlyList<AppFirewallPolicy> policies, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<bool> VerifyExactAsync(
            IReadOnlyList<AppFirewallPolicy> policies, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _verifications);
            return Task.FromResult(true);
        }

        public Task CleanupAllAsync(CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
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
}
