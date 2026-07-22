namespace WinSight.Firewall;

/// <summary>
/// Executes a validated <see cref="FirewallCommandRequest"/> against the durable policy
/// store and the outbound engine, producing a <see cref="FirewallCommandResponse"/>. It
/// is the only place that turns a request into an effect, so the named-pipe host stays a
/// thin transport. It is pure with respect to transport and fully unit-testable.
///
/// Safety invariants:
/// - An unauthenticated/unauthorised caller only ever receives <see cref="FirewallProtocolError.Unauthorized"/>.
/// - Store and engine failures collapse to <see cref="FirewallProtocolError.InternalFailure"/>;
///   no exception text ever crosses IPC.
/// - Promoting the persisted mode to enforcement is a mutation, so it needs
///   <see cref="FirewallCallerCapability.MutateMachinePolicy"/>: an elevated administrator or
///   SYSTEM. A caller holding only <see cref="FirewallCallerCapability.ReadStatus"/> — which is
///   what an unprivileged dashboard gets — can observe the machine but never arm it. The
///   privileged service, not the caller, performs the WFP mutation.
/// - Enforcement is refused outright when the engine cannot filter, rather than persisting a
///   mode that reports as armed while nothing is enforced.
/// </summary>
public sealed class FirewallRequestDispatcher
{
    private readonly FirewallPolicyStore _store;
    private readonly IFirewallMutationAuthority _authority;
    private readonly PendingOutboundLog _pending;

    /// <param name="pending">
    /// The apps observed reaching the network with no policy. Optional because a host that does
    /// not observe is a valid configuration; an empty log then reports honestly that nothing was
    /// seen, rather than the command failing.
    /// </param>
    public FirewallRequestDispatcher(
        FirewallPolicyStore store,
        IFirewallMutationAuthority authority,
        PendingOutboundLog? pending = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _authority = authority ?? throw new ArgumentNullException(nameof(authority));
        _pending = pending ?? new PendingOutboundLog();
    }

    public async Task<FirewallCommandResponse> DispatchAsync(
        FirewallCommandRequest request,
        bool callerAuthorised,
        CancellationToken cancellationToken = default) =>
        await DispatchAsync(request, callerAuthorised ? FirewallCallerCapability.MutateMachinePolicy : FirewallCallerCapability.None,
            cancellationToken).ConfigureAwait(false);

    public async Task<FirewallCommandResponse> DispatchAsync(
        FirewallCommandRequest request,
        FirewallCallerCapability capability,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (capability == FirewallCallerCapability.None ||
            (IsMutation(request.Command) && capability != FirewallCallerCapability.MutateMachinePolicy))
        {
            return Failure(request, FirewallProtocolError.Unauthorized);
        }

        try
        {
            return request.Command switch
            {
                FirewallCommand.GetStatus => await GetStatusAsync(request, cancellationToken).ConfigureAwait(false),
                FirewallCommand.ListPolicies => await ListPoliciesAsync(request, cancellationToken).ConfigureAwait(false),
                FirewallCommand.ListPending => await ListPendingAsync(request, cancellationToken).ConfigureAwait(false),
                FirewallCommand.UpsertPolicy => await UpsertPolicyAsync(request, cancellationToken).ConfigureAwait(false),
                FirewallCommand.RemovePolicy => await RemovePolicyAsync(request, cancellationToken).ConfigureAwait(false),
                FirewallCommand.EnableEnforcement => await EnableEnforcementAsync(request, cancellationToken).ConfigureAwait(false),
                FirewallCommand.EmergencyDisable => await EmergencyDisableAsync(request, cancellationToken).ConfigureAwait(false),
                _ => Failure(request, FirewallProtocolError.InvalidRequest),
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException
                                     or InvalidOperationException or ArgumentException)
        {
            // No exception detail crosses the wire: the caller learns only that the
            // command could not be completed.
            return Failure(request, FirewallProtocolError.InternalFailure);
        }
    }

    private static bool IsMutation(FirewallCommand command) => command is
        FirewallCommand.UpsertPolicy or FirewallCommand.RemovePolicy or
        FirewallCommand.EnableEnforcement or FirewallCommand.EmergencyDisable;

    private async Task<FirewallCommandResponse> GetStatusAsync(
        FirewallCommandRequest request, CancellationToken cancellationToken)
    {
        FirewallRuntimeStatus status;
        try
        {
            status = await _authority.GetRuntimeStatusAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (FirewallStorageTrustException)
        {
            return Failure(request, FirewallProtocolError.NotSupported);
        }
        return Success(request) with { Status = DescribeStatus(status) };
    }

    private async Task<FirewallCommandResponse> ListPoliciesAsync(
        FirewallCommandRequest request, CancellationToken cancellationToken)
    {
        var offset = request.Offset!.Value;
        var limit = request.Limit!.Value;

        var load = await _store.LoadOrAuditAsync(cancellationToken).ConfigureAwait(false);
        if (!load.StorageTrusted)
        {
            return Failure(request, FirewallProtocolError.NotSupported);
        }
        // Deterministic ordering so paging is stable across calls.
        var ordered = load.Configuration.Policies
            .OrderBy(policy => policy.ExecutablePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(policy => policy.ExecutablePath, StringComparer.Ordinal)
            .ToList();

        if (request.ProtocolVersion != FirewallProtocolCodec.CurrentVersion)
        {
            return offset != 0 || ordered.Count > limit
                ? Failure(request, FirewallProtocolError.NotSupported)
                : Success(request) with { Policies = ordered.ToArray() };
        }

        var snapshotVersion = FirewallSnapshotVersion.ForPolicies(ordered);
        if (offset > 0 && !string.Equals(
                request.SnapshotVersion, snapshotVersion, StringComparison.Ordinal))
        {
            return Failure(request, FirewallProtocolError.SnapshotChanged);
        }
        if (offset > ordered.Count)
        {
            return Failure(request, FirewallProtocolError.InvalidRequest);
        }

        var page = ordered.Skip(offset).Take(limit).ToArray();
        var consumed = offset + page.Length;
        int? nextOffset = consumed < ordered.Count ? consumed : null;

        return Success(request) with
        {
            Policies = page,
            NextOffset = nextOffset,
            SnapshotVersion = snapshotVersion,
            SnapshotCount = ordered.Count,
        };
    }

    /// <summary>
    /// The apps seen reaching the network that the operator has never ruled on. Paged like the
    /// policy list, and for the same reason: a page of long paths would otherwise overrun the
    /// message budget the codec enforces.
    /// </summary>
    private async Task<FirewallCommandResponse> ListPendingAsync(
        FirewallCommandRequest request, CancellationToken cancellationToken)
    {
        var offset = request.Offset!.Value;
        var limit = request.Limit!.Value;

        var load = await _store.LoadOrAuditAsync(cancellationToken).ConfigureAwait(false);
        if (!load.StorageTrusted)
        {
            return Failure(request, FirewallProtocolError.NotSupported);
        }

        // The observer already filters on a snapshot a few seconds old, so an app ruled on just
        // now could still be in the log. Filtering here too means the operator never sees a
        // decision they have already taken offered back to them.
        var ruled = load.Configuration.Policies
            .Select(policy => policy.ExecutablePath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var ordered = _pending.Snapshot()
            .Where(app => !ruled.Contains(app.ExecutablePath))
            .OrderByDescending(app => app.LastSeenUtc)
            .ThenBy(app => app.ExecutablePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(app => app.ExecutablePath, StringComparer.Ordinal)
            .ToList();

        if (request.ProtocolVersion != FirewallProtocolCodec.CurrentVersion)
        {
            return offset != 0 || ordered.Count > limit
                ? Failure(request, FirewallProtocolError.NotSupported)
                : Success(request) with { Pending = ordered.ToArray() };
        }

        var snapshotVersion = FirewallSnapshotVersion.ForPending(ordered);
        if (offset > 0 && !string.Equals(
                request.SnapshotVersion, snapshotVersion, StringComparison.Ordinal))
        {
            return Failure(request, FirewallProtocolError.SnapshotChanged);
        }
        if (offset > ordered.Count)
        {
            return Failure(request, FirewallProtocolError.InvalidRequest);
        }

        var page = ordered.Skip(offset).Take(limit).ToArray();
        var consumed = offset + page.Length;
        int? nextOffset = consumed < ordered.Count ? consumed : null;

        return Success(request) with
        {
            Pending = page,
            NextOffset = nextOffset,
            SnapshotVersion = snapshotVersion,
            SnapshotCount = ordered.Count,
        };
    }

    private async Task<FirewallCommandResponse> UpsertPolicyAsync(
        FirewallCommandRequest request, CancellationToken cancellationToken)
    {
        var policy = NormalisePolicy(request.Policy!);
        await _authority.UpsertPolicyAsync(policy, cancellationToken).ConfigureAwait(false);
        // Ruled on, so no longer pending: drop it now rather than let it linger until the
        // observer's snapshot goes stale and offer the operator a decision they just took.
        _pending.Resolve(policy.ExecutablePath);

        return Success(request);
    }

    private async Task<FirewallCommandResponse> RemovePolicyAsync(
        FirewallCommandRequest request, CancellationToken cancellationToken)
    {
        await _authority.RemovePolicyAsync(request.ExecutablePath!, cancellationToken).ConfigureAwait(false);

        return Success(request);
    }

    private async Task<FirewallCommandResponse> EnableEnforcementAsync(
        FirewallCommandRequest request, CancellationToken cancellationToken)
    {
        // Arming a machine whose engine cannot filter would persist Enforcement while every
        // stored block stays inert. The status would then read "audit-only" for a mode that
        // says otherwise, and the operator would believe the blocks are live. Refuse instead.
        if (!_authority.EngineSupported)
        {
            return Failure(request, FirewallProtocolError.NotSupported);
        }

        // The returned configuration is deliberately discarded: the status reported back is taken
        // from the authority afterwards, under its own serialization, so the reply can never mix a
        // pre-transition mode with a post-transition runtime state.
        _ = await _authority.EnableEnforcementAsync(cancellationToken).ConfigureAwait(false);

        return Success(request) with { Status = await DescribeStatusAsync(cancellationToken).ConfigureAwait(false) };
    }

    private async Task<FirewallCommandResponse> EmergencyDisableAsync(
        FirewallCommandRequest request, CancellationToken cancellationToken)
    {
        // The emergency path always returns the machine to audit-only, whatever the
        // stored mode was, and removes any engine state. It must succeed even from a
        // corrupt store, which LoadOrAuditAsync already guarantees.
        _ = await _authority.EmergencyDisableAsync(cancellationToken).ConfigureAwait(false);

        return Success(request) with { Status = await DescribeStatusAsync(cancellationToken).ConfigureAwait(false) };
    }

    private async Task<FirewallServiceStatus> DescribeStatusAsync(CancellationToken cancellationToken)
    {
        var status = await _authority.GetRuntimeStatusAsync(cancellationToken).ConfigureAwait(false);
        return DescribeStatus(status);
    }

    private FirewallServiceStatus DescribeStatus(FirewallRuntimeStatus status)
    {
        // The desired durable mode says what the service should attempt after a restart. It is
        // not evidence that native filters were applied. Only the serialized authority can
        // attest an active runtime state.
        var enforcementEnabled = status.EnforcementEnabled;
        // Carrying what the observer could not record keeps the blind spot visible: the dashboard
        // can say "and more were not recorded" instead of showing a truncated list as complete.
        return new FirewallServiceStatus(
            status.Mode, status.EngineSupported, enforcementEnabled, _pending.DroppedApps,
            status.EffectiveState);
    }

    private static AppFirewallPolicy NormalisePolicy(AppFirewallPolicy policy) =>
        policy with { ExecutablePath = OutboundPolicyEvaluator.CanonicalPath(policy.ExecutablePath) };

    private static FirewallCommandResponse Success(FirewallCommandRequest request) =>
        new(request.ProtocolVersion, request.RequestId, Success: true);

    private static FirewallCommandResponse Failure(
        FirewallCommandRequest request, FirewallProtocolError error) =>
        new(request.ProtocolVersion, request.RequestId, Success: false, error);
}
