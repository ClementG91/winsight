using System.Reflection;
using System.Text.Json;
using WinSight.Firewall;
using WinSight.FirewallService;

namespace WinSight.FirewallService.Tests;

internal static class TestEnforcementCoordinator
{
    public static EnforcementCoordinator Create(
        FirewallPolicyStore store,
        IOutboundFirewallEngine engine) =>
        Create(store, engine, new RecordingStartModeController());

    public static EnforcementCoordinator Create(
        FirewallPolicyStore store,
        IOutboundFirewallEngine engine,
        IFirewallServiceStartModeController startMode) =>
        new(store, new ExactReconcilerAdapter(store, engine), startMode);

    public static EnforcementCoordinator Create(
        FirewallPolicyStore store,
        Func<IOutboundFirewallEngine> engineFactory) =>
        new(store, () => new ExactReconcilerAdapter(store, engineFactory()),
            new RecordingStartModeController());
}

/// <summary>
/// Compatibility boundary for scenario fakes which predate the exact-inventory contract.
/// The coordinator only sees <see cref="IWinSightWfpReconciler"/>; this adapter models a
/// complete owned inventory and translates exact desired-state transitions into the old
/// per-path callbacks used to make ordering/failure assertions readable.
/// </summary>
internal sealed class ExactReconcilerAdapter : IWinSightWfpReconciler
{
    private readonly FirewallPolicyStore _store;
    private readonly IOutboundFirewallEngine _engine;
    private readonly Dictionary<string, AppFirewallPolicy> _inventory =
        new(StringComparer.OrdinalIgnoreCase);

    public ExactReconcilerAdapter(FirewallPolicyStore store, IOutboundFirewallEngine engine)
    {
        _store = store;
        _engine = engine;
        var persisted = ReadPersistedWithoutTrustEvaluation(store);
        if (persisted.Mode == OutboundFirewallMode.Enforcement)
        {
            foreach (var policy in Desired(persisted.Policies))
                _inventory[policy.ExecutablePath] = policy;
        }
    }

    public bool IsSupported => _engine.IsSupported;

    public async Task ReconcileExactAsync(
        IReadOnlyList<AppFirewallPolicy> policies,
        CancellationToken cancellationToken = default)
    {
        var desired = Desired(policies).ToDictionary(
            policy => policy.ExecutablePath, StringComparer.OrdinalIgnoreCase);
        var unchanged = _inventory.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase)
            .SetEquals(desired.Keys);
        foreach (var existing in _inventory.Keys.Where(path => !desired.ContainsKey(path)).ToList())
        {
            await _engine.RemoveAsync(existing, cancellationToken);
            _inventory.Remove(existing);
        }
        foreach (var policy in desired.Values.Where(policy =>
                     unchanged || !_inventory.ContainsKey(policy.ExecutablePath)))
        {
            // A native call may mutate WFP before returning an error. Model that state as
            // owned/possibly present so the following exact rollback must remove it.
            _inventory[policy.ExecutablePath] = policy;
            await _engine.ApplyAsync(policy, cancellationToken);
        }
    }

    public Task<bool> VerifyExactAsync(
        IReadOnlyList<AppFirewallPolicy> policies,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var desired = Desired(policies).Select(policy => policy.ExecutablePath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return Task.FromResult(_inventory.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(desired));
    }

    public async Task CleanupAllAsync(CancellationToken cancellationToken = default)
    {
        if (_engine is ITestWinSightFirewallCleanup cleanup)
        {
            var known = ReadPersistedWithoutTrustEvaluation(_store).Policies;
            _inventory.Clear();
            await cleanup.CleanupWinSightAsync(known, cancellationToken);
            return;
        }
        foreach (var path in _inventory.Keys.Reverse().ToList())
        {
            await _engine.RemoveAsync(path, cancellationToken);
            _inventory.Remove(path);
        }
    }

    private static IEnumerable<AppFirewallPolicy> Desired(IReadOnlyList<AppFirewallPolicy> policies) =>
        policies.Where(policy => policy.Enabled && policy.Action == OutboundAction.Block);

    private static OutboundFirewallConfiguration ReadPersistedWithoutTrustEvaluation(
        FirewallPolicyStore store)
    {
        var path = (string?)typeof(FirewallPolicyStore)
            .GetField("_path", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(store);
        if (path is null || !File.Exists(path)) return OutboundFirewallConfiguration.Empty;
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        var root = document.RootElement;
        var mode = Enum.Parse<OutboundFirewallMode>(root.GetProperty("mode").GetString()!, true);
        var policies = new List<AppFirewallPolicy>();
        foreach (var item in root.GetProperty("policies").EnumerateArray())
        {
            policies.Add(new AppFirewallPolicy(
                item.GetProperty("executablePath").GetString()!,
                Enum.Parse<OutboundAction>(item.GetProperty("action").GetString()!, true),
                !item.TryGetProperty("enabled", out var enabled) || enabled.GetBoolean()));
        }
        return new OutboundFirewallConfiguration(mode, policies);
    }
}

internal interface ITestWinSightFirewallCleanup
{
    Task CleanupWinSightAsync(
        IReadOnlyList<AppFirewallPolicy> knownPolicies,
        CancellationToken cancellationToken = default);
}

internal sealed class RecordingStartModeController(
    Action? onAutomatic = null,
    Action? onDemandStart = null) : IFirewallServiceStartModeController
{
    public List<string> Events { get; } = [];

    public Exception? AutomaticFailure { get; init; }

    public Exception? DemandStartFailure { get; init; }

    public void SetAutomatic()
    {
        Events.Add("automatic");
        onAutomatic?.Invoke();
        if (AutomaticFailure is not null) throw AutomaticFailure;
    }

    public void SetDemandStart()
    {
        Events.Add("demand");
        onDemandStart?.Invoke();
        if (DemandStartFailure is not null) throw DemandStartFailure;
    }
}
