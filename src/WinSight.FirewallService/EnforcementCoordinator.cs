using System.ComponentModel;
using WinSight.Firewall;

namespace WinSight.FirewallService;

/// <summary>
/// The service's sole machine-policy/WFP mutation authority. Every mutation is
/// serialized, freshly validates storage, and creates the native backend lazily only
/// after that validation. CLI processes never construct a second authority.
/// </summary>
public sealed class EnforcementCoordinator : IFirewallMutationAuthority, IDisposable, IAsyncDisposable
{
    private readonly FirewallPolicyStore _store;
    private readonly Func<IWinSightWfpReconciler> _reconcilerFactory;
    private readonly IFirewallServiceStartModeController _startMode;
    private readonly SemaphoreSlim _transition = new(1, 1);
    private readonly object _lifetimeLock = new();
    private readonly TaskCompletionSource _drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _disposeCompleted = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private IWinSightWfpReconciler? _reconciler;
    private int _outstanding;
    private bool _stopping;
    private bool _disposed;
    private int _effectiveState = (int)FirewallEnforcementState.AuditOnly;

    public EnforcementCoordinator(
        FirewallPolicyStore store,
        IWinSightWfpReconciler reconciler,
        IFirewallServiceStartModeController startMode)
        : this(store, () => reconciler, startMode)
    {
        ArgumentNullException.ThrowIfNull(reconciler);
    }

    public EnforcementCoordinator(
        FirewallPolicyStore store,
        Func<IWinSightWfpReconciler> reconcilerFactory,
        IFirewallServiceStartModeController startMode)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _reconcilerFactory = reconcilerFactory ?? throw new ArgumentNullException(nameof(reconcilerFactory));
        _startMode = startMode ?? throw new ArgumentNullException(nameof(startMode));
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
        FirewallRuntimeStatus? result = null;
        await LockedAsync(async () =>
        {
            var configuration = (await TrustedLoadAsync(cancellationToken).ConfigureAwait(false)).Configuration;
            var state = EffectiveState;
            if (state == FirewallEnforcementState.Active)
            {
                try
                {
                    var exact = await GetReconcilerAfterTrust()
                        .VerifyExactAsync(configuration.Policies, cancellationToken).ConfigureAwait(false);
                    if (!exact)
                    {
                        SetEffectiveState(FirewallEnforcementState.Degraded);
                        state = FirewallEnforcementState.Degraded;
                    }
                }
                catch (Exception verificationFailure) when (
                    IsTransitionFailure(verificationFailure)
                    && !cancellationToken.IsCancellationRequested)
                {
                    SetEffectiveState(FirewallEnforcementState.Degraded);
                    state = FirewallEnforcementState.Degraded;
                }
            }
            result = new FirewallRuntimeStatus(configuration.Mode, EngineSupported, state);
        }, cancellationToken).ConfigureAwait(false);
        return result!;
    }

    public Task SetPolicyAsync(string executablePath, OutboundAction action, CancellationToken cancellationToken = default) =>
        UpsertPolicyAsync(new AppFirewallPolicy(executablePath, action), cancellationToken);

    public async Task UpsertPolicyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
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
                var reconciler = GetReconcilerAfterTrust();
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
                var reconciler = GetReconcilerAfterTrust();
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
                await GetReconcilerAfterTrust().CleanupAllAsync(cancellationToken).ConfigureAwait(false);
                SetEffectiveState(FirewallEnforcementState.AuditOnly);
                return;
            }
            IWinSightWfpReconciler? reconciler = null;
            try
            {
                reconciler = GetReconcilerAfterTrust();
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
            var reconciler = GetReconcilerAfterTrust();
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
            var configuration = (await TrustedLoadAsync(cancellationToken).ConfigureAwait(false)).Configuration;
            var reconciler = GetReconcilerAfterTrust();
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
            _startMode.SetDemandStart();
        }, cancellationToken).ConfigureAwait(false);
        return result;
    }

    private static async Task RestoreEnforcementOrThrowAsync(
        IWinSightWfpReconciler reconciler,
        OutboundFirewallConfiguration configuration,
        Exception cause,
        string rollbackCode)
    {
        if (configuration.Mode != OutboundFirewallMode.Enforcement) return;
        try
        {
            await ReconcileAndVerifyAsync(
                reconciler, configuration.Policies, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception rollbackFailure) when (IsTransitionFailure(rollbackFailure))
        {
            throw RollbackFailed(rollbackCode, cause, rollbackFailure);
        }
    }

    private IWinSightWfpReconciler GetReconcilerAfterTrust() =>
        _reconciler ??= _reconcilerFactory()
            ?? throw new InvalidOperationException("The WFP reconciler factory returned null.");

    private async Task RollbackToAuditOnlyAsync(
        IWinSightWfpReconciler? reconciler,
        OutboundFirewallConfiguration original,
        Exception cause,
        string rollbackCode)
    {
        var failures = new List<Exception>();
        try
        {
            await (reconciler ?? GetReconcilerAfterTrust())
                .CleanupAllAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception rollbackFailure) when (IsTransitionFailure(rollbackFailure))
        {
            failures.Add(rollbackFailure);
        }
        try
        {
            await _store.SaveAsync(original with { Mode = OutboundFirewallMode.AuditOnly }, CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (Exception rollbackFailure) when (IsTransitionFailure(rollbackFailure))
        {
            failures.Add(rollbackFailure);
        }
        try
        {
            _startMode.SetDemandStart();
        }
        catch (Exception rollbackFailure) when (IsTransitionFailure(rollbackFailure))
        {
            failures.Add(rollbackFailure);
        }
        if (failures.Count != 0)
        {
            throw RollbackFailed(rollbackCode, cause, new AggregateException(failures));
        }
    }

    private async Task RollbackEnableAsync(
        IWinSightWfpReconciler? reconciler,
        OutboundFirewallConfiguration original,
        Exception cause,
        string rollbackCode) =>
        await RollbackToAuditOnlyAsync(reconciler, original, cause, rollbackCode).ConfigureAwait(false);

    private static async Task ReconcileAndVerifyAsync(
        IWinSightWfpReconciler reconciler,
        IReadOnlyList<AppFirewallPolicy> policies,
        CancellationToken cancellationToken)
    {
        await reconciler.ReconcileExactAsync(policies, cancellationToken).ConfigureAwait(false);
        if (!await reconciler.VerifyExactAsync(policies, cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException("The reconciled WFP state could not be proven exact.");
        }
    }

    private static bool IsTransitionFailure(Exception exception) => exception is
        Win32Exception or IOException or UnauthorizedAccessException or InvalidDataException or
        InvalidOperationException or OperationCanceledException;

    private void SetEffectiveState(FirewallEnforcementState state) =>
        Volatile.Write(ref _effectiveState, (int)state);

    private static FirewallTransitionException RollbackFailed(string code, Exception cause, Exception rollback) =>
        new(code, new AggregateException(cause, rollback));

    private async Task<FirewallPolicyLoadResult> TrustedLoadAsync(CancellationToken cancellationToken)
    {
        var load = await _store.LoadOrAuditAsync(cancellationToken).ConfigureAwait(false);
        if (!load.StorageTrusted)
        {
            throw new FirewallStorageTrustException(load.Diagnostic ?? "StorageInspectionFailed");
        }
        return load;
    }

    private async Task LockedAsync(Func<Task> action, CancellationToken cancellationToken)
    {
        lock (_lifetimeLock)
        {
            ObjectDisposedException.ThrowIf(_stopping || _disposed, this);
            _outstanding++;
        }
        try
        {
            await _transition.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { await action().ConfigureAwait(false); }
            finally { _transition.Release(); }
        }
        finally
        {
            lock (_lifetimeLock)
            {
                _outstanding--;
                if (_stopping && _outstanding == 0) _drained.TrySetResult();
            }
        }
    }

    private Task LockedTransitionAsync(Func<Task> action, CancellationToken cancellationToken) =>
        LockedAsync(async () =>
        {
            try
            {
                await action().ConfigureAwait(false);
            }
            catch (Exception failure) when (IsTransitionFailure(failure))
            {
                // This write must occur before LockedAsync releases _transition. Otherwise a
                // queued status read can acquire the lock and publish stale Active/AuditOnly.
                SetEffectiveState(FirewallEnforcementState.Degraded);
                throw;
            }
        }, cancellationToken);

    private static bool PathEquals(string left, string right) =>
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();

    public async ValueTask DisposeAsync()
    {
        Task drain;
        bool disposeOwner;
        lock (_lifetimeLock)
        {
            if (_disposed) return;
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
            if (_reconciler is IAsyncDisposable asyncReconciler)
                await asyncReconciler.DisposeAsync().ConfigureAwait(false);
            else (_reconciler as IDisposable)?.Dispose();
            lock (_lifetimeLock)
            {
                _disposed = true;
                _transition.Dispose();
            }
            _disposeCompleted.TrySetResult();
        }
        catch (Exception ex)
        {
            _disposeCompleted.TrySetException(ex);
            throw;
        }
    }
}

public sealed class FirewallTransitionException : IOException
{
    public FirewallTransitionException(string code, Exception innerException)
        : base("The firewall transition failed.", innerException) => Code = code;
    public string Code { get; }
}
