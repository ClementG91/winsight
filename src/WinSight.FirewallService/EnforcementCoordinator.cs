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
    private readonly Func<IOutboundFirewallEngine> _engineFactory;
    private readonly SemaphoreSlim _transition = new(1, 1);
    private readonly object _lifetimeLock = new();
    private readonly TaskCompletionSource _drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _disposeCompleted = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private IOutboundFirewallEngine? _engine;
    private int _outstanding;
    private bool _stopping;
    private bool _disposed;

    public EnforcementCoordinator(FirewallPolicyStore store, IOutboundFirewallEngine engine)
        : this(store, () => engine)
    {
        ArgumentNullException.ThrowIfNull(engine);
    }

    public EnforcementCoordinator(FirewallPolicyStore store, Func<IOutboundFirewallEngine> engineFactory)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _engineFactory = engineFactory ?? throw new ArgumentNullException(nameof(engineFactory));
    }

    public bool EngineSupported => true;

    public Task SetPolicyAsync(string executablePath, OutboundAction action, CancellationToken cancellationToken = default) =>
        UpsertPolicyAsync(new AppFirewallPolicy(executablePath, action), cancellationToken);

    public async Task UpsertPolicyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var path = OutboundPolicyEvaluator.CanonicalPath(policy.ExecutablePath);
        await LockedAsync(async () =>
        {
            var configuration = (await TrustedLoadAsync(cancellationToken).ConfigureAwait(false)).Configuration;
            var normalized = policy with { ExecutablePath = path };
            var policies = configuration.Policies
                .Where(existing => !PathEquals(existing.ExecutablePath, path))
                .Append(normalized).ToList();
            if (configuration.Mode == OutboundFirewallMode.Enforcement)
            {
                var engine = GetEngineAfterTrust();
                var previous = configuration.Policies.FirstOrDefault(existing => PathEquals(existing.ExecutablePath, path));
                try
                {
                    await engine.ApplyAsync(normalized, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception applyFailure) when (IsTransitionFailure(applyFailure))
                {
                    try
                    {
                        if (previous is null) await engine.RemoveAsync(path, CancellationToken.None).ConfigureAwait(false);
                        else await engine.ApplyAsync(previous, CancellationToken.None).ConfigureAwait(false);
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
                        if (previous is null) await engine.RemoveAsync(path, CancellationToken.None).ConfigureAwait(false);
                        else await engine.ApplyAsync(previous, CancellationToken.None).ConfigureAwait(false);
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
        await LockedAsync(async () =>
        {
            var configuration = (await TrustedLoadAsync(cancellationToken).ConfigureAwait(false)).Configuration;
            var remaining = configuration.Policies.Where(policy => !PathEquals(policy.ExecutablePath, path)).ToList();
            if (configuration.Mode == OutboundFirewallMode.Enforcement)
            {
                var engine = GetEngineAfterTrust();
                var previous = configuration.Policies.FirstOrDefault(policy => PathEquals(policy.ExecutablePath, path));
                try
                {
                    await engine.RemoveAsync(path, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception removeFailure) when (IsTransitionFailure(removeFailure))
                {
                    try
                    {
                        if (previous is not null) await engine.ApplyAsync(previous, CancellationToken.None).ConfigureAwait(false);
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
                        if (previous is not null) await engine.ApplyAsync(previous, CancellationToken.None).ConfigureAwait(false);
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
        await LockedAsync(async () =>
        {
            var configuration = (await TrustedLoadAsync(cancellationToken).ConfigureAwait(false)).Configuration;
            if (configuration.Mode != OutboundFirewallMode.Enforcement) return;
            IOutboundFirewallEngine? engine = null;
            var applied = new List<AppFirewallPolicy>();
            try
            {
                engine = GetEngineAfterTrust();
                foreach (var policy in configuration.Policies.Where(policy => policy.Action == OutboundAction.Block))
                {
                    applied.Add(policy);
                    await engine.ApplyAsync(policy, cancellationToken).ConfigureAwait(false);
                }
            }
            catch (Exception applyFailure) when (IsTransitionFailure(applyFailure))
            {
                await RollbackPartialApplyAsync(
                    engine, applied, configuration, applyFailure, "StartupApplyRollbackFailed").ConfigureAwait(false);
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
        await LockedAsync(async () =>
        {
            var configuration = (await TrustedLoadAsync(cancellationToken).ConfigureAwait(false)).Configuration;
            var enforcing = configuration with { Mode = OutboundFirewallMode.Enforcement };
            await _store.SaveAsync(enforcing, cancellationToken).ConfigureAwait(false);
            IOutboundFirewallEngine? engine = null;
            var applied = new List<AppFirewallPolicy>();
            try
            {
                engine = GetEngineAfterTrust();
                foreach (var policy in configuration.Policies.Where(policy => policy.Action == OutboundAction.Block))
                {
                    applied.Add(policy);
                    await engine.ApplyAsync(policy, cancellationToken).ConfigureAwait(false);
                }
            }
            catch (Exception applyFailure) when (IsTransitionFailure(applyFailure))
            {
                await RollbackPartialApplyAsync(
                    engine, applied, configuration, applyFailure, "EnableRollbackFailed").ConfigureAwait(false);
                if (applyFailure is OperationCanceledException) throw;
                throw new FirewallTransitionException("EnableApplyFailed", applyFailure);
            }
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
        await LockedAsync(async () =>
        {
            var configuration = (await TrustedLoadAsync(cancellationToken).ConfigureAwait(false)).Configuration;
            var engine = GetEngineAfterTrust();
            try
            {
                if (engine is IWinSightFirewallCleanup cleanup)
                {
                    await cleanup.CleanupWinSightAsync(configuration.Policies, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    foreach (var policy in configuration.Policies)
                    {
                        await engine.RemoveAsync(policy.ExecutablePath, cancellationToken).ConfigureAwait(false);
                    }
                }
            }
            catch (Exception cleanupFailure) when (IsTransitionFailure(cleanupFailure))
            {
                await RestoreEnforcementOrThrowAsync(
                    engine, configuration, cleanupFailure, "EmergencyCleanupRollbackFailed").ConfigureAwait(false);
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
                    engine, configuration, saveFailure, "EmergencyPersistenceRollbackFailed").ConfigureAwait(false);
                if (saveFailure is OperationCanceledException) throw;
                throw new FirewallTransitionException("EmergencyPersistenceFailed", saveFailure);
            }
        }, cancellationToken).ConfigureAwait(false);
        return result;
    }

    private static async Task RestoreEnforcementOrThrowAsync(
        IOutboundFirewallEngine engine,
        OutboundFirewallConfiguration configuration,
        Exception cause,
        string rollbackCode)
    {
        if (configuration.Mode != OutboundFirewallMode.Enforcement) return;
        try
        {
            foreach (var policy in configuration.Policies.Where(policy => policy.Action == OutboundAction.Block))
            {
                await engine.ApplyAsync(policy, CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch (Exception rollbackFailure) when (IsTransitionFailure(rollbackFailure))
        {
            throw RollbackFailed(rollbackCode, cause, rollbackFailure);
        }
    }

    private IOutboundFirewallEngine GetEngineAfterTrust() => _engine ??= _engineFactory();

    private async Task RollbackPartialApplyAsync(
        IOutboundFirewallEngine? engine,
        IReadOnlyList<AppFirewallPolicy> applied,
        OutboundFirewallConfiguration original,
        Exception cause,
        string rollbackCode)
    {
        try
        {
            if (engine is not null)
            {
                foreach (var policy in applied.Reverse())
                    await engine.RemoveAsync(policy.ExecutablePath, CancellationToken.None).ConfigureAwait(false);
            }
            await _store.SaveAsync(original with { Mode = OutboundFirewallMode.AuditOnly }, CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (Exception rollbackFailure) when (IsTransitionFailure(rollbackFailure))
        {
            throw RollbackFailed(rollbackCode, cause, rollbackFailure);
        }
    }

    private static bool IsTransitionFailure(Exception exception) => exception is
        Win32Exception or IOException or UnauthorizedAccessException or InvalidDataException or
        InvalidOperationException or OperationCanceledException;

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
            if (_engine is IAsyncDisposable asyncEngine) await asyncEngine.DisposeAsync().ConfigureAwait(false);
            else (_engine as IDisposable)?.Dispose();
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
