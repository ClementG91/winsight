using WinSight.Firewall;

namespace WinSight.FirewallService;

/// <summary>
/// Bridges the durable policy store and the outbound engine: it applies stored Block
/// policies to the engine, clears them, sets a single app's policy, and reads or changes
/// the persisted enforcement mode. It is engine-agnostic (audit-only or WFP), so its
/// behaviour is unit-tested with a fake engine and a real temporary store, and the service
/// uses it both at startup (re-apply blocks) and from the enforcement verbs.
///
/// The service constructs its store with enforcement persistence enabled; this type never
/// decides on its own to enforce. Turning enforcement on is an explicit caller action.
/// </summary>
public sealed class EnforcementCoordinator
{
    private readonly FirewallPolicyStore _store;
    private readonly IOutboundFirewallEngine _engine;

    public EnforcementCoordinator(FirewallPolicyStore store, IOutboundFirewallEngine engine)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
    }

    /// <summary>Applies every stored Block policy to the engine (used at service startup).</summary>
    public async Task ApplyBlocksAsync(CancellationToken cancellationToken = default)
    {
        var configuration = (await _store.LoadOrAuditAsync(cancellationToken).ConfigureAwait(false)).Configuration;
        foreach (var policy in configuration.Policies.Where(policy => policy.Action == OutboundAction.Block))
        {
            await _engine.ApplyAsync(policy, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Lifts every stored policy's filter (fail-safe unblock on disable).</summary>
    public async Task ClearBlocksAsync(CancellationToken cancellationToken = default)
    {
        var configuration = (await _store.LoadOrAuditAsync(cancellationToken).ConfigureAwait(false)).Configuration;
        foreach (var policy in configuration.Policies)
        {
            await _engine.RemoveAsync(policy.ExecutablePath, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Persists a per-application decision and applies it live: Block installs the filter,
    /// Allow/Ask lift it. The stored mode is left unchanged.
    /// </summary>
    public async Task SetPolicyAsync(
        string executablePath, OutboundAction action, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);

        var configuration = (await _store.LoadOrAuditAsync(cancellationToken).ConfigureAwait(false)).Configuration;
        var policy = new AppFirewallPolicy(executablePath, action);
        var policies = configuration.Policies
            .Where(existing => !PathEquals(existing.ExecutablePath, executablePath))
            .Append(policy)
            .ToList();

        await _store.SaveAsync(configuration with { Policies = policies }, cancellationToken).ConfigureAwait(false);
        await _engine.ApplyAsync(policy, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The persisted enforcement mode.</summary>
    public async Task<OutboundFirewallMode> GetModeAsync(CancellationToken cancellationToken = default) =>
        (await _store.LoadOrAuditAsync(cancellationToken).ConfigureAwait(false)).Configuration.Mode;

    /// <summary>
    /// Enables enforcement: persists Enforcement mode and applies every stored Block policy.
    /// </summary>
    public async Task EnableAsync(CancellationToken cancellationToken = default)
    {
        var configuration = (await _store.LoadOrAuditAsync(cancellationToken).ConfigureAwait(false)).Configuration;
        await _store.SaveAsync(
            configuration with { Mode = OutboundFirewallMode.Enforcement }, cancellationToken).ConfigureAwait(false);
        await ApplyBlocksAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Disables enforcement: lifts every filter first (so nothing stays blocked), then
    /// persists audit-only mode. Clearing before persisting keeps it fail-safe.
    /// </summary>
    public async Task DisableAsync(CancellationToken cancellationToken = default)
    {
        await ClearBlocksAsync(cancellationToken).ConfigureAwait(false);
        var configuration = (await _store.LoadOrAuditAsync(cancellationToken).ConfigureAwait(false)).Configuration;
        await _store.SaveAsync(
            configuration with { Mode = OutboundFirewallMode.AuditOnly }, cancellationToken).ConfigureAwait(false);
    }

    private static bool PathEquals(string left, string right) =>
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}
