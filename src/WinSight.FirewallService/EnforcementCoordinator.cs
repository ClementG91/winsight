using WinSight.Firewall;

namespace WinSight.FirewallService;

/// <summary>
/// The service's sole machine-policy/WFP mutation authority. Every mutation is serialized and
/// freshly validates storage before using it. The sole exception is emergency cleanup: an
/// authenticated administrator may remove WinSight-owned WFP state without trusting or touching
/// the policy file. CLI processes never construct a second authority.
/// </summary>
/// <remarks>
/// Teardown is asynchronous and this type therefore exposes <b>only</b> <see cref="IAsyncDisposable"/>.
/// It used to also implement <see cref="IDisposable"/>, bridged with
/// <c>DisposeAsync().AsTask().GetAwaiter().GetResult()</c> — the sync-over-async pattern this
/// project's own standards forbid, on the shutdown path of a SYSTEM service. Nothing ever used it:
/// the host, the validation probe and every test already dispose with <c>await using</c>. A
/// synchronous entry point that can only be implemented by blocking is not a convenience, it is a
/// deadlock waiting for the one caller who takes it.
/// </remarks>
public sealed partial class EnforcementCoordinator : IFirewallMutationAuthority, IAsyncDisposable
{
    private static readonly TimeSpan DefaultStatusVerificationTimeout = TimeSpan.FromSeconds(1);

    /// <summary>
    /// How long a runtime status is served from memory before it is established again.
    /// </summary>
    /// <remarks>
    /// <b>What this closes.</b> A status read takes the same lock every mutation takes, and under
    /// it performs a full path-trust inspection and an exhaustive verification of the machine's WFP
    /// filters - native work the caller cannot abort. Reading is a capability granted to any
    /// interactive user, so an unprivileged caller could hold that lock in a loop and delay an
    /// elevated administrator's EmergencyDisable. The careful separation of read and mutate
    /// capabilities at the pipe was undone one storey down.
    ///
    /// A short-lived cache bounds it: however many callers ask, the expensive path runs at most
    /// once per lifetime. Two seconds is long enough that a loop cannot drive it and short enough
    /// that an operator watching the dashboard sees a transition promptly - and every mutation
    /// invalidates the cache, so a read taken straight after a transition still reports the truth.
    ///
    /// It is a cache of an observation, not of a decision: the value served is one this service
    /// established itself, within the last two seconds.
    /// </remarks>
    private static readonly TimeSpan StatusCacheLifetime = TimeSpan.FromSeconds(2);

    private readonly FirewallPolicyStore _store;
    private readonly Func<IWinSightWfpReconciler> _reconcilerFactory;
    private readonly IFirewallServiceStartModeController _startMode;
    private readonly TimeSpan _statusVerificationTimeout;
    private readonly SemaphoreSlim _transition = new(1, 1);
    private readonly object _lifetimeLock = new();
    private readonly TaskCompletionSource _drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _disposeCompleted = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private IWinSightWfpReconciler? _reconciler;
    private Task<bool>? _runtimeVerification;
    private FirewallRuntimeStatus? _cachedStatus;
    private long _cachedStatusAt;
    private int _outstanding;
    private bool _stopping;
    private bool _disposed;
    private int _effectiveState = (int)FirewallEnforcementState.AuditOnly;

    public EnforcementCoordinator(
        FirewallPolicyStore store,
        IWinSightWfpReconciler reconciler,
        IFirewallServiceStartModeController startMode,
        TimeSpan? statusVerificationTimeout = null)
        : this(store, () => reconciler, startMode, statusVerificationTimeout)
    {
        ArgumentNullException.ThrowIfNull(reconciler);
    }

    public EnforcementCoordinator(
        FirewallPolicyStore store,
        Func<IWinSightWfpReconciler> reconcilerFactory,
        IFirewallServiceStartModeController startMode,
        TimeSpan? statusVerificationTimeout = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _reconcilerFactory = reconcilerFactory ?? throw new ArgumentNullException(nameof(reconcilerFactory));
        _startMode = startMode ?? throw new ArgumentNullException(nameof(startMode));
        _statusVerificationTimeout = ValidateStatusVerificationTimeout(
            statusVerificationTimeout ?? DefaultStatusVerificationTimeout);
    }

    public bool EngineSupported => true;

    public FirewallEnforcementState EffectiveState =>
        (FirewallEnforcementState)Volatile.Read(ref _effectiveState);

    /// <summary>
    /// Takes the durable requested mode and runtime proof under the transition lock. This avoids
    /// constructing an impossible IPC status from a pre-transition mode and post-transition
    /// effective state (or the reverse) while enable/disable is in flight.
    /// </summary>
    public async Task<FirewallRuntimeStatus> GetRuntimeStatusAsync(
        CancellationToken cancellationToken = default)
    {
        // Served from the cache when it is fresh, without taking the transition lock at all. This
        // is the half of the fix that matters: an unprivileged reader can no longer queue ahead of
        // an administrator's transition, however often it asks.
        if (ReadCachedStatus() is { } cached)
        {
            return cached;
        }

        FirewallRuntimeStatus? result = null;
        await LockedAsync(async () =>
        {
            // Checked again now the lock is held. Readers that arrived together all missed the
            // cache outside it, and without this every one of them would run its own verification -
            // the burst case, which is exactly the shape a caller trying to apply pressure uses.
            if (ReadCachedStatus() is { } fresh)
            {
                result = fresh;
                return;
            }
            var configuration = (await TrustedLoadAsync(cancellationToken).ConfigureAwait(false)).Configuration;
            var state = EffectiveState;
            if (state == FirewallEnforcementState.Active)
            {
                var exactlyVerified = false;
                try
                {
                    exactlyVerified = await VerifyRuntimeStatusAsync(
                        GetReconciler(), configuration.Policies, cancellationToken)
                        .ConfigureAwait(false);
                }
                finally
                {
                    // Exact success is the only exit which may leave Active observable. This
                    // invariant is independent of exception type and mutable cancellation state;
                    // any original failure continues to propagate after the fail-closed write.
                    if (!exactlyVerified)
                    {
                        SetEffectiveState(FirewallEnforcementState.Degraded);
                        state = FirewallEnforcementState.Degraded;
                    }
                }
            }
            result = new FirewallRuntimeStatus(configuration.Mode, EngineSupported, state);
            PublishStatus(result);
        }, cancellationToken).ConfigureAwait(false);
        return result!;
    }

    public Task SetPolicyAsync(string executablePath, OutboundAction action, CancellationToken cancellationToken = default) =>
        UpsertPolicyAsync(new AppFirewallPolicy(executablePath, action), cancellationToken);

    public async Task UpsertPolicyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
        // Ask is the absence of a durable ruling: user-mode WFP cannot suspend a connection while
        // waiting for UI, and retaining an Ask row made the observer classify the app as already
        // ruled forever. Treating Ask as removal restores observation and makes the next outbound
        // connection appear in the pending list instead of silently allowing it indefinitely.
        if (policy.Action == OutboundAction.Ask)
        {
            await RemovePolicyAsync(policy.ExecutablePath, cancellationToken).ConfigureAwait(false);
            return;
        }
        var path = OutboundPolicyEvaluator.CanonicalPath(policy.ExecutablePath);
        await LockedTransitionAsync(async () =>
        {
            var configuration = (await TrustedLoadAsync(cancellationToken).ConfigureAwait(false)).Configuration;
            var normalized = policy with { ExecutablePath = path };
            var policies = configuration.Policies
                .Where(existing => !PathEquals(existing.ExecutablePath, path))
                .Append(normalized).ToList();
            if (configuration.Mode == OutboundFirewallMode.Enforcement)
            {
                var reconciler = GetReconciler();
                try
                {
                    await ReconcileAndVerifyAsync(reconciler, policies, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception applyFailure) when (IsTransitionFailure(applyFailure))
                {
                    try
                    {
                        await ReconcileAndVerifyAsync(
                            reconciler, configuration.Policies, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch (Exception rollbackFailure) when (IsTransitionFailure(rollbackFailure))
                    {
                        throw RollbackFailed("UpsertApplyRollbackFailed", applyFailure, rollbackFailure);
                    }
                    if (applyFailure is OperationCanceledException) throw;
                    throw new FirewallTransitionException("UpsertApplyFailed", applyFailure);
                }
                try
                {
                    await _store.SaveAsync(configuration with { Policies = policies }, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception saveFailure) when (IsTransitionFailure(saveFailure))
                {
                    try
                    {
                        await ReconcileAndVerifyAsync(
                            reconciler, configuration.Policies, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch (Exception rollbackFailure) when (IsTransitionFailure(rollbackFailure))
                    {
                        throw RollbackFailed("UpsertRollbackFailed", saveFailure, rollbackFailure);
                    }
                    if (saveFailure is OperationCanceledException) throw;
                    throw new FirewallTransitionException("UpsertPersistenceFailed", saveFailure);
                }
                return;
            }
            await _store.SaveAsync(configuration with { Policies = policies }, cancellationToken).ConfigureAwait(false);
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task RemovePolicyAsync(string executablePath, CancellationToken cancellationToken = default)
    {
        var path = OutboundPolicyEvaluator.CanonicalPath(executablePath);
        await LockedTransitionAsync(async () =>
        {
            var configuration = (await TrustedLoadAsync(cancellationToken).ConfigureAwait(false)).Configuration;
            var remaining = configuration.Policies.Where(policy => !PathEquals(policy.ExecutablePath, path)).ToList();
            if (configuration.Mode == OutboundFirewallMode.Enforcement)
            {
                var reconciler = GetReconciler();
                try
                {
                    await ReconcileAndVerifyAsync(reconciler, remaining, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception removeFailure) when (IsTransitionFailure(removeFailure))
                {
                    try
                    {
                        await ReconcileAndVerifyAsync(
                            reconciler, configuration.Policies, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch (Exception rollbackFailure) when (IsTransitionFailure(rollbackFailure))
                    {
                        throw RollbackFailed("RemoveApplyRollbackFailed", removeFailure, rollbackFailure);
                    }
                    if (removeFailure is OperationCanceledException) throw;
                    throw new FirewallTransitionException("RemoveApplyFailed", removeFailure);
                }
                try
                {
                    await _store.SaveAsync(configuration with { Policies = remaining }, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception saveFailure) when (IsTransitionFailure(saveFailure))
                {
                    try
                    {
                        await ReconcileAndVerifyAsync(
                            reconciler, configuration.Policies, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch (Exception rollbackFailure) when (IsTransitionFailure(rollbackFailure))
                    {
                        throw RollbackFailed("RemoveRollbackFailed", saveFailure, rollbackFailure);
                    }
                    if (saveFailure is OperationCanceledException) throw;
                    throw new FirewallTransitionException("RemovePersistenceFailed", saveFailure);
                }
                return;
            }
            await _store.SaveAsync(configuration with { Policies = remaining }, cancellationToken).ConfigureAwait(false);
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task ApplyBlocksAsync(CancellationToken cancellationToken = default)
    {
        await LockedTransitionAsync(async () =>
        {
            var configuration = (await TrustedLoadAsync(cancellationToken).ConfigureAwait(false)).Configuration;
            if (configuration.Mode != OutboundFirewallMode.Enforcement)
            {
                await GetReconciler().CleanupAllAsync(cancellationToken).ConfigureAwait(false);
                SetEffectiveState(FirewallEnforcementState.AuditOnly);
                return;
            }
            IWinSightWfpReconciler? reconciler = null;
            try
            {
                reconciler = GetReconciler();
                // Boot persistence is part of the same serialized authority transition as WFP.
                // A failure also drives the complete owned namespace through cleanup.
                _startMode.SetAutomatic();
                await ReconcileAndVerifyAsync(
                    reconciler, configuration.Policies, cancellationToken).ConfigureAwait(false);
                SetEffectiveState(FirewallEnforcementState.Active);
            }
            catch (Exception applyFailure) when (IsTransitionFailure(applyFailure))
            {
                await RollbackToAuditOnlyAsync(
                    reconciler, configuration, applyFailure, "StartupApplyRollbackFailed").ConfigureAwait(false);
                if (applyFailure is OperationCanceledException) throw;
                throw new FirewallTransitionException("StartupApplyFailed", applyFailure);
            }
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<OutboundFirewallMode> GetModeAsync(CancellationToken cancellationToken = default)
    {
        var result = OutboundFirewallMode.AuditOnly;
        await LockedAsync(async () =>
        {
            result = (await TrustedLoadAsync(cancellationToken).ConfigureAwait(false)).Configuration.Mode;
        }, cancellationToken).ConfigureAwait(false);
        return result;
    }

    public async Task EnableAsync(CancellationToken cancellationToken = default) =>
        _ = await EnableEnforcementAsync(cancellationToken).ConfigureAwait(false);

    public async Task<OutboundFirewallConfiguration> EnableEnforcementAsync(
        CancellationToken cancellationToken = default)
    {
        var result = OutboundFirewallConfiguration.Empty;
        await LockedTransitionAsync(async () =>
        {
            var configuration = (await TrustedLoadAsync(cancellationToken).ConfigureAwait(false)).Configuration;
            var enforcing = configuration with { Mode = OutboundFirewallMode.Enforcement };
            // Auto-start is established first: reporting Active while the service remains
            // demand-start would silently lose enforcement after reboot.
            var reconciler = GetReconciler();
            try
            {
                _startMode.SetAutomatic();
            }
            catch (Exception startModeFailure) when (IsTransitionFailure(startModeFailure))
            {
                await RollbackEnableAsync(
                    reconciler, configuration, startModeFailure, "EnableStartModeRollbackFailed")
                    .ConfigureAwait(false);
                throw new FirewallTransitionException("EnableStartModeFailed", startModeFailure);
            }
            try
            {
                await _store.SaveAsync(enforcing, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception persistenceFailure) when (IsTransitionFailure(persistenceFailure))
            {
                await RollbackEnableAsync(
                    null, configuration, persistenceFailure, "EnablePersistenceRollbackFailed")
                    .ConfigureAwait(false);
                if (persistenceFailure is OperationCanceledException) throw;
                throw new FirewallTransitionException("EnablePersistenceFailed", persistenceFailure);
            }
            try
            {
                await ReconcileAndVerifyAsync(
                    reconciler, enforcing.Policies, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception applyFailure) when (IsTransitionFailure(applyFailure))
            {
                await RollbackEnableAsync(
                    reconciler, configuration, applyFailure, "EnableRollbackFailed").ConfigureAwait(false);
                if (applyFailure is OperationCanceledException) throw;
                throw new FirewallTransitionException("EnableApplyFailed", applyFailure);
            }
            SetEffectiveState(FirewallEnforcementState.Active);
            result = enforcing;
        }, cancellationToken).ConfigureAwait(false);
        return result;
    }

    public async Task DisableAsync(CancellationToken cancellationToken = default) =>
        _ = await EmergencyDisableAsync(cancellationToken).ConfigureAwait(false);

    public async Task<OutboundFirewallConfiguration> EmergencyDisableAsync(
        CancellationToken cancellationToken = default)
    {
        var result = OutboundFirewallConfiguration.Empty;
        await LockedTransitionAsync(async () =>
        {
            // Emergency disable must be able to remove WinSight-owned WFP state even when policy
            // storage is untrusted. The store result is used only to decide whether durable intent
            // may be repaired; it never gates cleanup and untrusted content is never opened.
            var emergencyLoad = await _store.LoadOrAuditAsync(cancellationToken).ConfigureAwait(false);
            var configuration = emergencyLoad.Configuration;
            var reconciler = GetReconciler();
            try
            {
                await reconciler.CleanupAllAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception cleanupFailure) when (IsTransitionFailure(cleanupFailure))
            {
                await RestoreEnforcementOrThrowAsync(
                    reconciler, configuration, cleanupFailure, "EmergencyCleanupRollbackFailed").ConfigureAwait(false);
                if (cleanupFailure is OperationCanceledException) throw;
                throw new FirewallTransitionException("EmergencyCleanupFailed", cleanupFailure);
            }

            if (!emergencyLoad.StorageTrusted)
            {
                // Runtime recovery succeeded, but durable intent cannot be touched through an
                // untrusted path. Demand-start prevents automatic re-entry; the coded failure is
                // deliberately propagated so the dispatcher writes a sanitized audit event.
                SetEffectiveState(FirewallEnforcementState.AuditOnly);
                SetDemandStartOrThrow();
                throw new FirewallTransitionException(
                    "EmergencyStorageUntrusted",
                    new FirewallStorageTrustException(
                        emergencyLoad.Diagnostic ?? "StorageInspectionFailed"));
            }

            result = configuration with { Mode = OutboundFirewallMode.AuditOnly };
            try
            {
                await _store.SaveAsync(result, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception saveFailure) when (IsTransitionFailure(saveFailure))
            {
                await RestoreEnforcementOrThrowAsync(
                    reconciler, configuration, saveFailure, "EmergencyPersistenceRollbackFailed").ConfigureAwait(false);
                if (saveFailure is OperationCanceledException) throw;
                throw new FirewallTransitionException("EmergencyPersistenceFailed", saveFailure);
            }
            // At this point filters are gone and AuditOnly is durable. If SCM refuses demand-start,
            // fail and publish Degraded, but never reapply filters or restore Enforcement intent.
            SetEffectiveState(FirewallEnforcementState.AuditOnly);
            SetDemandStartOrThrow();
        }, cancellationToken).ConfigureAwait(false);
        return result;
    }

    public async ValueTask DisposeAsync()
    {
        Task drain;
        bool disposeOwner;
        lock (_lifetimeLock)
        {
            disposeOwner = !_stopping;
            _stopping = true;
            if (_outstanding == 0) _drained.TrySetResult();
            drain = _drained.Task;
        }
        await drain.ConfigureAwait(false);
        if (!disposeOwner)
        {
            await _disposeCompleted.Task.ConfigureAwait(false);
            return;
        }
        try
        {
            IWinSightWfpReconciler? reconciler;
            Task<bool>? unfinishedVerification;
            lock (_lifetimeLock)
            {
                reconciler = _reconciler;
                _reconciler = null;
                unfinishedVerification = _runtimeVerification is { IsCompleted: false }
                    ? _runtimeVerification
                    : null;
                _runtimeVerification = null;
                _transition.Dispose();
            }

            if (reconciler is not null)
            {
                if (unfinishedVerification is null)
                {
                    await DisposeReconcilerAsync(reconciler).ConfigureAwait(false);
                }
                else
                {
                    // The native read cannot be safely aborted or awaited without making service
                    // shutdown unbounded. Transfer sole reconciler ownership to a completion task;
                    // it disposes only after the read ends, while DisposeAsync returns promptly.
                    _ = DisposeReconcilerAfterVerificationAsync(unfinishedVerification, reconciler);
                }
            }
            lock (_lifetimeLock) _disposed = true;
            _disposeCompleted.TrySetResult();
        }
        catch (Exception ex)
        {
            lock (_lifetimeLock) _disposed = true;
            _disposeCompleted.TrySetException(ex);
            throw;
        }
    }

    private static async Task DisposeReconcilerAfterVerificationAsync(
        Task verification,
        IWinSightWfpReconciler reconciler)
    {
        try
        {
            await verification.ConfigureAwait(false);
        }
        catch (Exception)
        {
            // A late verification failure is already fail-closed and must not prevent disposal.
        }

        try
        {
            await DisposeReconcilerAsync(reconciler).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // DisposeAsync has already returned after transferring ownership. Observe any late
            // disposal failure so it cannot become an unobserved task exception.
        }
    }

    private static async ValueTask DisposeReconcilerAsync(IWinSightWfpReconciler reconciler)
    {
        if (reconciler is IAsyncDisposable asyncReconciler)
            await asyncReconciler.DisposeAsync().ConfigureAwait(false);
        else (reconciler as IDisposable)?.Dispose();
    }
}
