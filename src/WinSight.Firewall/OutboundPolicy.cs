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

/// <summary>Pure policy lookup shared by the future service, prompt UI and tests.</summary>
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

    internal static string CanonicalPath(string executablePath)
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
/// Privileged WFP boundary. The implementation will live in a least-privilege
/// Windows service; neither the dashboard nor the scanner libraries mutate WFP.
/// </summary>
public interface IOutboundFirewallEngine
{
    bool IsSupported { get; }

    Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default);

    Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default);
}
