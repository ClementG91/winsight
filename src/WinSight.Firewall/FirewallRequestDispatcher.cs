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
/// - The dispatcher never promotes the persisted mode to enforcement. Enabling
///   enforcement is a separate, later, explicitly gated increment.
/// </summary>
public sealed class FirewallRequestDispatcher
{
    private readonly FirewallPolicyStore _store;
    private readonly IFirewallMutationAuthority _authority;

    public FirewallRequestDispatcher(FirewallPolicyStore store, IFirewallMutationAuthority authority)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _authority = authority ?? throw new ArgumentNullException(nameof(authority));
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
                FirewallCommand.UpsertPolicy => await UpsertPolicyAsync(request, cancellationToken).ConfigureAwait(false),
                FirewallCommand.RemovePolicy => await RemovePolicyAsync(request, cancellationToken).ConfigureAwait(false),
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
        FirewallCommand.UpsertPolicy or FirewallCommand.RemovePolicy or FirewallCommand.EmergencyDisable;

    private async Task<FirewallCommandResponse> GetStatusAsync(
        FirewallCommandRequest request, CancellationToken cancellationToken)
    {
        var load = await _store.LoadOrAuditAsync(cancellationToken).ConfigureAwait(false);
        if (!load.StorageTrusted)
        {
            return Failure(request, FirewallProtocolError.NotSupported);
        }
        return Success(request) with { Status = DescribeStatus(load.Configuration.Mode) };
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
            .ToList();

        var page = ordered.Skip(offset).Take(limit).ToArray();
        var consumed = offset + page.Length;
        int? nextOffset = consumed < ordered.Count ? consumed : null;

        return Success(request) with { Policies = page, NextOffset = nextOffset };
    }

    private async Task<FirewallCommandResponse> UpsertPolicyAsync(
        FirewallCommandRequest request, CancellationToken cancellationToken)
    {
        await _authority.UpsertPolicyAsync(NormalisePolicy(request.Policy!), cancellationToken).ConfigureAwait(false);

        return Success(request);
    }

    private async Task<FirewallCommandResponse> RemovePolicyAsync(
        FirewallCommandRequest request, CancellationToken cancellationToken)
    {
        await _authority.RemovePolicyAsync(request.ExecutablePath!, cancellationToken).ConfigureAwait(false);

        return Success(request);
    }

    private async Task<FirewallCommandResponse> EmergencyDisableAsync(
        FirewallCommandRequest request, CancellationToken cancellationToken)
    {
        // The emergency path always returns the machine to audit-only, whatever the
        // stored mode was, and removes any engine state. It must succeed even from a
        // corrupt store, which LoadOrAuditAsync already guarantees.
        var configuration = await _authority.EmergencyDisableAsync(cancellationToken).ConfigureAwait(false);

        return Success(request) with { Status = DescribeStatus(configuration.Mode) };
    }

    private FirewallServiceStatus DescribeStatus(OutboundFirewallMode mode)
    {
        var enforcementEnabled = mode == OutboundFirewallMode.Enforcement && _authority.EngineSupported;
        return new FirewallServiceStatus(mode, _authority.EngineSupported, enforcementEnabled);
    }

    private static AppFirewallPolicy NormalisePolicy(AppFirewallPolicy policy) =>
        policy with { ExecutablePath = OutboundPolicyEvaluator.CanonicalPath(policy.ExecutablePath) };

    private static FirewallCommandResponse Success(FirewallCommandRequest request) =>
        new(request.ProtocolVersion, request.RequestId, Success: true);

    private static FirewallCommandResponse Failure(
        FirewallCommandRequest request, FirewallProtocolError error) =>
        new(request.ProtocolVersion, request.RequestId, Success: false, error);
}
