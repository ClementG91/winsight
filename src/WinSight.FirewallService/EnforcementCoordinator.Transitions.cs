using System.ComponentModel;
using System.Diagnostics;
using WinSight.Firewall;

namespace WinSight.FirewallService;

public sealed partial class EnforcementCoordinator
{
    private void SetDemandStartOrThrow()
    {
        try
        {
            _startMode.SetDemandStart();
        }
        catch (Exception failure) when (IsTransitionFailure(failure))
        {
            throw new FirewallTransitionException("EmergencyStartModeFailed", failure);
        }
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

    private IWinSightWfpReconciler GetReconciler() =>
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
            await (reconciler ?? GetReconciler())
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
        // An involuntary fall back to audit-only is not the same fact as an operator choosing it,
        // and reporting them identically is what made this dangerous. The stored mode is genuinely
        // AuditOnly — nothing is filtered and saying otherwise would overstate protection — but the
        // effective state says the machine arrived here through a failure. Without this the status
        // read exactly like a deliberately unarmed machine, so an attacker who provoked the
        // rollback left no trace an operator could see.
        SetEffectiveState(FirewallEnforcementState.Degraded);

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

    private async Task<bool> VerifyRuntimeStatusAsync(
        IWinSightWfpReconciler reconciler,
        IReadOnlyList<AppFirewallPolicy> policies,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = new CancellationTokenSource(_statusVerificationTimeout);
        using var verificationCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken, deadline.Token);
        var verificationToken = verificationCancellation.Token;

        // The production verifier enters synchronous WFP P/Invoke before returning its Task.
        // Invoke it on the thread pool so even that synchronous portion cannot retain the
        // coordinator lock past the deadline. A native call cannot be forcefully aborted, so a
        // timed-out read may finish in the background. VerifyExactAsync is read-only, its late
        // result is deliberately ignored, and Active is downgraded before the lock is released.
        // This permits a later serialized transition to recover without replaying or timing out
        // any mutation.
        Task<bool> verification;
        lock (_lifetimeLock)
        {
            // A timed-out native read can be unabortable. Until it completes, fail closed
            // without starting another worker so recovery/status cycles cannot accumulate
            // detached reads against the shared reconciler.
            if (_runtimeVerification is { IsCompleted: false } inFlight)
            {
                cancellationToken.ThrowIfCancellationRequested();
                // Joined rather than refused. Returning false here meant that a verification which
                // had exceeded its one-second deadline and was still running in the background made
                // the *next* status read fail immediately - and a failed verification downgrades
                // the machine to Degraded until the next explicit successful transition. A slow
                // native read was therefore reported as a firewall that had stopped filtering.
                //
                // Joining keeps the property this branch exists for - no second detached read
                // against the shared reconciler - while answering with the verification's actual
                // result. The caller's own deadline still applies.
                //
                // The joined task was started against the policy list as it stood when it began,
                // which may no longer be this caller's. That is safe in the only direction that
                // matters: the verification is exact, so a list that has since gained a policy
                // cannot match a WFP state that has gained the matching filter, and the answer is
                // false - Degraded, fail-closed. It cannot report exact for a policy set whose
                // filters are missing, because the missing filter is precisely what exactness
                // tests. A transition that failed to install has already set Degraded anyway, and
                // this whole branch is only reached while the state is still Active.
                verification = inFlight;
            }
            else
            {
                verification = Task.Run(
                    () => reconciler.VerifyExactAsync(policies, verificationToken),
                    CancellationToken.None);
                _runtimeVerification = verification;
            }
        }

        TrackRuntimeVerification(verification);
        try
        {
            return await verification.WaitAsync(verificationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (
            deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            return false;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw;
        }
    }

    private void TrackRuntimeVerification(Task<bool> verification) =>
        _ = verification.ContinueWith(
            completed =>
            {
                // Observe a late failure because the status request may already have timed out.
                _ = completed.Exception;
                lock (_lifetimeLock)
                {
                    if (ReferenceEquals(_runtimeVerification, completed))
                        _runtimeVerification = null;
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);

    private static TimeSpan ValidateStatusVerificationTimeout(TimeSpan timeout) =>
        timeout > TimeSpan.Zero && timeout <= TimeSpan.FromMinutes(1)
            ? timeout
            : throw new ArgumentOutOfRangeException(
                nameof(timeout),
                "The status verification timeout must be greater than zero and no more than one minute.");

    private static bool IsTransitionFailure(Exception exception) => exception is
        Win32Exception or IOException or UnauthorizedAccessException or InvalidDataException or
        InvalidOperationException or OperationCanceledException;

    private void SetEffectiveState(FirewallEnforcementState state)
    {
        Volatile.Write(ref _effectiveState, (int)state);
        // Any change to the effective state makes a cached status a statement about the past.
        InvalidateStatus();
    }

    /// <summary>The cached status when it is still current, or null.</summary>
    private FirewallRuntimeStatus? ReadCachedStatus()
    {
        var status = Volatile.Read(ref _cachedStatus);
        if (status is null)
        {
            return null;
        }
        var age = Stopwatch.GetElapsedTime(Volatile.Read(ref _cachedStatusAt));
        return age <= StatusCacheLifetime ? status : null;
    }

    /// <summary>Remembers a status this service just established.</summary>
    private void PublishStatus(FirewallRuntimeStatus status)
    {
        // The timestamp is written first, so a reader can never see a fresh timestamp against a
        // stale value - only the harmless reverse, which expires the entry.
        Volatile.Write(ref _cachedStatusAt, Stopwatch.GetTimestamp());
        Volatile.Write(ref _cachedStatus, status);
    }

    private void InvalidateStatus() => Volatile.Write(ref _cachedStatus, null);

    private static FirewallTransitionException RollbackFailed(string code, Exception cause, Exception rollback) =>
        new(code, new AggregateException(cause, rollback));

    private async Task<FirewallPolicyLoadResult> TrustedLoadAsync(CancellationToken cancellationToken)
    {
        var load = await _store.LoadOrAuditAsync(cancellationToken).ConfigureAwait(false);
        if (!load.StorageTrusted)
        {
            throw new FirewallStorageTrustException(load.Diagnostic ?? "StorageInspectionFailed");
        }
        if (load.RecoveredToAuditOnly)
        {
            throw new InvalidDataException("The firewall policy content is invalid.");
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
}
