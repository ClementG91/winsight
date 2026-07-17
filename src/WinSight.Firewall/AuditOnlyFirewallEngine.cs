namespace WinSight.Firewall;

/// <summary>
/// Non-mutating fallback and test engine. It records no native effect and can never prove
/// filtering. Production service composition uses the WFP-backed engine only behind the
/// trusted, serialized authority; this fallback remains useful where native filtering is
/// deliberately unavailable.
/// </summary>
public sealed class AuditOnlyFirewallEngine : IOutboundFirewallEngine
{
    /// <summary>Audit-only never enforces, so enforcement can never be claimed as active.</summary>
    public bool IsSupported => false;

    public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }

    public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }
}
