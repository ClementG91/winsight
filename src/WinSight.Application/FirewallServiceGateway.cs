using WinSight.Firewall;

namespace WinSight.Application;

/// <summary>
/// A read-only view of the firewall service for the dashboard: whether the privileged
/// service is reachable, its mode, whether enforcement is active, and the stored
/// policies. When the service is not installed or not running, the view degrades to
/// "unavailable, audit-only" instead of surfacing an error, so the dashboard stays
/// usable and never implies the machine is being filtered when it is not.
/// </summary>
/// <param name="Pending">
/// Applications seen reaching the network that have never been ruled on, newest first.
/// </param>
/// <param name="UnrecordedApps">
/// How many further apps the service could not record. Surfaced rather than dropped so the list is
/// never presented as complete when it is not.
/// </param>
public sealed record FirewallServiceView(
    bool ServiceAvailable,
    OutboundFirewallMode Mode,
    bool EnforcementEnabled,
    IReadOnlyList<AppFirewallPolicy> Policies,
    IReadOnlyList<PendingOutboundApp> Pending,
    int UnrecordedApps = 0,
    FirewallEnforcementState EffectiveState = FirewallEnforcementState.AuditOnly)
{
    public static FirewallServiceView Unavailable { get; } =
        new(false, OutboundFirewallMode.AuditOnly, EnforcementEnabled: false, [], []);
}

/// <summary>Outcome of a firewall policy mutation requested from the dashboard side.</summary>
public enum FirewallMutationResult
{
    /// <summary>The service accepted and applied the change.</summary>
    Applied,

    /// <summary>The service is not installed, not running, or did not reply in time.</summary>
    ServiceUnavailable,

    /// <summary>The caller's Windows identity is not permitted to change policy.</summary>
    Unauthorized,

    /// <summary>
    /// The machine cannot do what was asked — it has no usable outbound engine, so
    /// enforcement could never filter. Distinct from <see cref="Rejected"/> because telling
    /// an operator "rejected" when the real answer is "this machine cannot filter at all"
    /// invites them to believe a retry would protect them.
    /// </summary>
    NotSupported,

    /// <summary>The service rejected the request (invalid or internal failure).</summary>
    Rejected,
}

/// <summary>
/// Talks to the local firewall service over the authenticated pipe. It projects a status
/// read into a <see cref="FirewallServiceView"/>, and requests policy mutations
/// (set/remove one app, emergency-disable) that the privileged service authorises by the
/// caller's Windows identity. Transport faults (no service, timeout, malformed reply)
/// collapse to <see cref="FirewallServiceView.Unavailable"/> or
/// <see cref="FirewallMutationResult.ServiceUnavailable"/>, so the dashboard never implies
/// the machine is filtered when it is not. Enabling enforcement is requested here too, but
/// the request is only a request: the privileged service performs the WFP mutation and
/// authorises it by the caller's Windows identity, so an unprivileged dashboard is refused
/// and only an elevated one can arm the machine.
/// </summary>
public sealed class FirewallServiceGateway
{
    private static readonly TimeSpan DefaultConnectTimeout = TimeSpan.FromSeconds(2);
    // Static for process lifetime: no per-window disposable synchronization primitive is left
    // behind when the dashboard reconstructs a gateway.
    private static readonly SemaphoreSlim ProtocolNegotiation = new(1, 1);

    private readonly IFirewallServiceClient _client;
    private readonly TimeSpan _connectTimeout;
    private int _negotiatedProtocolVersion;

    public FirewallServiceGateway(IFirewallServiceClient client, TimeSpan? connectTimeout = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _connectTimeout = connectTimeout ?? DefaultConnectTimeout;
    }

    public async Task<FirewallServiceView> GetViewAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var status = await SendAsync(
                Request(FirewallCommand.GetStatus), cancellationToken).ConfigureAwait(false);
            if (!status.Success || status.Status is null)
            {
                return FirewallServiceView.Unavailable;
            }

            var policies = await ListAllAsync(cancellationToken).ConfigureAwait(false);
            var pending = await ListAllPendingAsync(cancellationToken).ConfigureAwait(false);
            // Collection assembly can span several IPC calls. Re-read runtime truth last
            // and construct the view only from that final observation, so a mid-page WFP
            // degradation can never leave a stale Active view on screen.
            var finalStatus = await SendAsync(
                Request(FirewallCommand.GetStatus), cancellationToken).ConfigureAwait(false);
            if (!finalStatus.Success || finalStatus.Status is null)
            {
                return FirewallServiceView.Unavailable;
            }
            return new FirewallServiceView(
                ServiceAvailable: true,
                finalStatus.Status.Mode,
                finalStatus.Status.EnforcementEnabled,
                policies,
                pending,
                finalStatus.Status.UnrecordedApps,
                finalStatus.Status.EffectiveState);
        }
        catch (Exception ex) when (ex is TimeoutException or FirewallProtocolException or IOException)
        {
            return FirewallServiceView.Unavailable;
        }
    }

    /// <summary>Sets one application's policy (allow/block/ask) and asks the service to apply it.</summary>
    public Task<FirewallMutationResult> SetPolicyAsync(
        AppFirewallPolicy policy, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return MutateAsync(
            new FirewallCommandRequest(
                FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(),
                FirewallCommand.UpsertPolicy, Policy: policy),
            cancellationToken);
    }

    /// <summary>Removes one application's policy and asks the service to lift any filter.</summary>
    public Task<FirewallMutationResult> RemovePolicyAsync(
        string executablePath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        return MutateAsync(
            new FirewallCommandRequest(
                FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(),
                FirewallCommand.RemovePolicy, ExecutablePath: executablePath),
            cancellationToken);
    }

    /// <summary>
    /// Arms the machine: promotes it to enforcement so the stored blocks start filtering.
    /// The service refuses this unless the caller is elevated, and refuses it outright when
    /// the machine has no usable engine, so a success here means traffic really is filtered.
    /// </summary>
    public Task<FirewallMutationResult> EnableEnforcementAsync(CancellationToken cancellationToken = default) =>
        MutateAsync(
            new FirewallCommandRequest(
                FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.EnableEnforcement),
            cancellationToken);

    /// <summary>Returns the machine to audit-only and lifts every filter (fail-safe kill switch).</summary>
    public Task<FirewallMutationResult> EmergencyDisableAsync(CancellationToken cancellationToken = default) =>
        MutateAsync(
            new FirewallCommandRequest(
                FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.EmergencyDisable),
            cancellationToken);

    private async Task<FirewallMutationResult> MutateAsync(
        FirewallCommandRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (response.Success)
            {
                return FirewallMutationResult.Applied;
            }
            return response.Error switch
            {
                FirewallProtocolError.Unauthorized => FirewallMutationResult.Unauthorized,
                FirewallProtocolError.NotSupported => FirewallMutationResult.NotSupported,
                _ => FirewallMutationResult.Rejected,
            };
        }
        catch (Exception ex) when (ex is TimeoutException or FirewallProtocolException or IOException)
        {
            return FirewallMutationResult.ServiceUnavailable;
        }
    }

    private async Task<IReadOnlyList<PendingOutboundApp>> ListAllPendingAsync(CancellationToken cancellationToken)
    {
        var all = new List<PendingOutboundApp>();
        var offset = 0;
        string? snapshotVersion = null;
        int? snapshotCount = null;
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Bounded for the same reason as the policy list: a misbehaving service that never
        // advances the offset must not spin the dashboard forever.
        const int maxPages = (PendingOutboundLog.MaxPendingApps / FirewallProtocolCodec.MaxPoliciesPerMessage) + 4;
        for (var page = 0; page < maxPages; page++)
        {
            var response = await SendAsync(
                Request(FirewallCommand.ListPending, offset: offset,
                    limit: FirewallProtocolCodec.MaxPoliciesPerMessage, snapshotVersion: snapshotVersion),
                cancellationToken).ConfigureAwait(false);
            if (!response.Success || response.Pending is null)
            {
                throw IncompletePagination();
            }

            ValidateSnapshotPage(response, offset, snapshotVersion, snapshotCount,
                PendingOutboundLog.MaxPendingApps, response.Pending.Length);
            snapshotVersion ??= response.SnapshotVersion;
            snapshotCount ??= response.ProtocolVersion == FirewallProtocolCodec.CurrentVersion
                ? response.SnapshotCount
                : response.Pending.Length;
            foreach (var app in response.Pending)
            {
                if (!paths.Add(app.ExecutablePath)) throw IncompletePagination();
                all.Add(app);
            }
            if (response.NextOffset is not { } next)
            {
                if (all.Count != snapshotCount) throw IncompletePagination();
                return all;
            }
            if (response.Pending.Length == 0
                || next != checked(offset + response.Pending.Length))
            {
                throw IncompletePagination();
            }
            offset = next;
        }
        throw IncompletePagination();
    }

    private async Task<IReadOnlyList<AppFirewallPolicy>> ListAllAsync(CancellationToken cancellationToken)
    {
        var all = new List<AppFirewallPolicy>();
        var offset = 0;
        string? snapshotVersion = null;
        int? snapshotCount = null;
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Bounded: MaxPolicyCount / page size, with headroom, so a misbehaving service
        // that never advances the offset cannot spin forever.
        const int maxPages = (FirewallPolicyStore.MaxPolicyCount / FirewallProtocolCodec.MaxPoliciesPerMessage) + 4;
        for (var page = 0; page < maxPages; page++)
        {
            var response = await SendAsync(
                Request(FirewallCommand.ListPolicies, offset: offset,
                    limit: FirewallProtocolCodec.MaxPoliciesPerMessage, snapshotVersion: snapshotVersion),
                cancellationToken).ConfigureAwait(false);
            if (!response.Success || response.Policies is null)
            {
                throw IncompletePagination();
            }

            ValidateSnapshotPage(response, offset, snapshotVersion, snapshotCount,
                FirewallPolicyStore.MaxPolicyCount, response.Policies.Length);
            snapshotVersion ??= response.SnapshotVersion;
            snapshotCount ??= response.ProtocolVersion == FirewallProtocolCodec.CurrentVersion
                ? response.SnapshotCount
                : response.Policies.Length;
            foreach (var policy in response.Policies)
            {
                if (!paths.Add(policy.ExecutablePath)) throw IncompletePagination();
                all.Add(policy);
            }
            if (response.NextOffset is not { } next)
            {
                if (all.Count != snapshotCount) throw IncompletePagination();
                return all;
            }
            if (response.Policies.Length == 0
                || next != checked(offset + response.Policies.Length))
            {
                throw IncompletePagination();
            }
            offset = next;
        }

        throw IncompletePagination();
    }

    private async Task<FirewallCommandResponse> SendAsync(
        FirewallCommandRequest request, CancellationToken cancellationToken)
    {
        var version = await GetProtocolVersionAsync(cancellationToken).ConfigureAwait(false);
        return await _client.SendAsync(
            request with { ProtocolVersion = version }, _connectTimeout, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Probe v3, then v2, then v1 with a read-only status request before sending any mutation.
    /// Only an authenticated close before the first response byte permits the next lower probe.
    /// No timeout, malformed frame, partial reply or generic I/O fault can downgrade or cache.
    /// </summary>
    private async Task<int> GetProtocolVersionAsync(CancellationToken cancellationToken)
    {
        var cached = Volatile.Read(ref _negotiatedProtocolVersion);
        if (cached != 0) return cached;

        await ProtocolNegotiation.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            cached = _negotiatedProtocolVersion;
            if (cached != 0) return cached;
            var probe = new FirewallCommandRequest(
                FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus);
            try
            {
                var response = await _client.SendAsync(
                    probe, _connectTimeout, cancellationToken).ConfigureAwait(false);
                ValidateNegotiationProbe(response);
                Volatile.Write(ref _negotiatedProtocolVersion, FirewallProtocolCodec.CurrentVersion);
            }
            catch (FirewallLegacyPeerClosedException)
            {
                var runtimeProofProbe = probe with { ProtocolVersion = FirewallProtocolCodec.RuntimeProofVersion };
                try
                {
                    var response = await _client.SendAsync(
                        runtimeProofProbe, _connectTimeout, cancellationToken).ConfigureAwait(false);
                    ValidateNegotiationProbe(response);
                    Volatile.Write(ref _negotiatedProtocolVersion, FirewallProtocolCodec.RuntimeProofVersion);
                }
                catch (FirewallLegacyPeerClosedException)
                {
                    var legacyProbe = probe with { ProtocolVersion = FirewallProtocolCodec.LegacyVersion };
                    var response = await _client.SendAsync(
                        legacyProbe, _connectTimeout, cancellationToken).ConfigureAwait(false);
                    ValidateNegotiationProbe(response);
                    Volatile.Write(ref _negotiatedProtocolVersion, FirewallProtocolCodec.LegacyVersion);
                }
            }
            return _negotiatedProtocolVersion;
        }
        finally
        {
            ProtocolNegotiation.Release();
        }
    }

    private static FirewallCommandRequest Request(
        FirewallCommand command, int? offset = null, int? limit = null, string? snapshotVersion = null) =>
        new(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), command, Offset: offset, Limit: limit,
            SnapshotVersion: snapshotVersion);

    private static FirewallProtocolException IncompletePagination() =>
        new(FirewallProtocolError.InvalidRequest, "Firewall service pagination is incomplete.");

    private static void ValidateNegotiationProbe(FirewallCommandResponse response)
    {
        if (!response.Success || response.Status is null)
        {
            throw new FirewallProtocolException(
                FirewallProtocolError.InvalidRequest,
                "Firewall service protocol negotiation failed.");
        }
    }

    private static void ValidateSnapshotPage(
        FirewallCommandResponse response,
        int offset,
        string? expectedVersion,
        int? expectedCount,
        int maximumCount,
        int pageCount)
    {
        if (response.ProtocolVersion == FirewallProtocolCodec.CurrentVersion)
        {
            if (!FirewallProtocolCodec.IsSnapshotVersion(response.SnapshotVersion)
                || response.SnapshotCount is not { } count
                || count < 0 || count > maximumCount
                || (expectedVersion is not null
                    && !string.Equals(expectedVersion, response.SnapshotVersion, StringComparison.Ordinal))
                || (expectedCount is not null && expectedCount != count)
                || offset + pageCount > count
                || (response.NextOffset is null && offset + pageCount != count)
                || (response.NextOffset is not null && offset + pageCount >= count))
            {
                throw IncompletePagination();
            }
            return;
        }

        // v1/v2 have no snapshot contract and are safe only as one complete page.
        if (offset != 0 || response.NextOffset is not null
            || response.SnapshotVersion is not null || response.SnapshotCount is not null
            || pageCount > maximumCount)
        {
            throw IncompletePagination();
        }
    }
}
