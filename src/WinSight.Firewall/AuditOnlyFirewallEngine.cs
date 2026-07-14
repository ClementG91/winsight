namespace WinSight.Firewall;

/// <summary>
/// The default Phase 2 engine: it never mutates the Windows Filtering Platform. Policy
/// decisions are recorded and persisted, but no filter is installed, so a machine can
/// never lose connectivity through WinSight while enforcement is still being built and
/// independently safety-tested. <see cref="IsSupported"/> is deliberately false, which
/// makes the dispatcher refuse to report enforcement as active.
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
