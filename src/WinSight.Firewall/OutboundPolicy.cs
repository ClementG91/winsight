namespace WinSight.Firewall;

/// <summary>The user-visible decision for a program's outbound traffic.</summary>
public enum OutboundAction
{
    Ask,
    Allow,
    Block,
}

/// <summary>
/// A path-scoped outbound policy. Phase 2 deliberately keys rules by canonical
/// executable path; display names and process ids are mutable and unsafe identities.
/// </summary>
public sealed record AppFirewallPolicy(string ExecutablePath, OutboundAction Action, bool Enabled = true);

/// <summary>Pure policy lookup shared by the firewall service, prompt UI and tests.</summary>
public sealed class OutboundPolicyEvaluator
{
    private readonly Dictionary<string, OutboundAction> _policies;

    public OutboundPolicyEvaluator(
        IEnumerable<AppFirewallPolicy> policies,
        OutboundAction defaultAction = OutboundAction.Ask)
    {
        DefaultAction = defaultAction;
        var indexed = new Dictionary<string, OutboundAction>(StringComparer.OrdinalIgnoreCase);
        foreach (var policy in policies.Where(policy => policy.Enabled))
        {
            var path = CanonicalPath(policy.ExecutablePath);
            if (!indexed.TryAdd(path, policy.Action))
            {
                throw new ArgumentException($"Duplicate firewall policy for '{path}'.", nameof(policies));
            }
        }
        _policies = indexed;
    }

    public OutboundAction DefaultAction { get; }

    public OutboundAction Evaluate(string executablePath) =>
        _policies.TryGetValue(CanonicalPath(executablePath), out var action)
            ? action
            : DefaultAction;

    /// <summary>
    /// The single canonical form for a policy's executable path: quote-stripped, required
    /// to be absolute, and fully normalized. Shared by the store, the IPC dispatcher, the
    /// CLI enforcement path, and the WFP key derivation so every layer agrees on identity.
    /// Throws <see cref="ArgumentException"/> for a blank or non-absolute path.
    /// </summary>
    public static string CanonicalPath(string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        var path = executablePath.Trim().Trim('"');
        if (!Path.IsPathFullyQualified(path))
        {
            throw new ArgumentException("Firewall policy paths must be absolute.", nameof(executablePath));
        }
        return Path.GetFullPath(path);
    }
}

/// <summary>
/// Privileged WFP boundary. The implementation lives in a least-privilege Windows service;
/// neither the dashboard nor the scanner libraries mutate WFP.
///
/// Note on cancellation: the WFP-backed implementation wraps synchronous native RPCs, so it
/// honours <paramref name="cancellationToken"/> only at entry — a call already in flight
/// runs to completion. Callers should treat these as short, effectively non-cancellable
/// operations (they complete in milliseconds) rather than long-running cancellable work.
/// </summary>
public interface IOutboundFirewallEngine
{
    bool IsSupported { get; }

    Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default);

    Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default);
}

/// <summary>The single serialized authority for machine-policy and WFP mutation.</summary>
public interface IFirewallMutationAuthority
{
    bool EngineSupported { get; }

    /// <summary>
    /// Runtime truth for this service lifetime. This is never inferred from the persisted mode:
    /// after a failed startup or transition it remains <see cref="FirewallEnforcementState.Degraded"/>
    /// until an explicit successful recovery transition.
    /// </summary>
    FirewallEnforcementState EffectiveState => FirewallEnforcementState.AuditOnly;

    /// <summary>
    /// Reads the requested durable mode and runtime enforcement state as one coherent
    /// observation. Implementations which own transitions must take this snapshot under the
    /// same serialization boundary as mutations. The conservative default preserves source
    /// compatibility for non-production authorities and never claims filtering is active.
    /// </summary>
    Task<FirewallRuntimeStatus> GetRuntimeStatusAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(new FirewallRuntimeStatus(
            OutboundFirewallMode.AuditOnly,
            EngineSupported,
            FirewallEnforcementState.AuditOnly));

    Task UpsertPolicyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default);

    Task RemovePolicyAsync(string executablePath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Promotes the machine to enforcement and applies every stored block. Enforcement is
    /// default-permit: with no stored block this changes no traffic, and each block then
    /// filters exactly the app the operator named. A partial apply rolls back, so the call
    /// either reaches enforcement with every block live or leaves the previous state intact.
    /// Callers must refuse this when the engine is unsupported rather than persist a mode
    /// that filters nothing, which would read as protection that is not there.
    /// </summary>
    Task<OutboundFirewallConfiguration> EnableEnforcementAsync(CancellationToken cancellationToken = default);

    Task<OutboundFirewallConfiguration> EmergencyDisableAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// A coherent service-side observation. <see cref="EffectiveState"/> is runtime proof, not a
/// restatement of <see cref="Mode"/>; callers must only present filtering as active when it is
/// <see cref="FirewallEnforcementState.Active"/>.
/// </summary>
public sealed record FirewallRuntimeStatus(
    OutboundFirewallMode Mode,
    bool EngineSupported,
    FirewallEnforcementState EffectiveState)
{
    public bool EnforcementEnabled => EffectiveState == FirewallEnforcementState.Active;
}
