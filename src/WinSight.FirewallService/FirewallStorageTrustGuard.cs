using WinSight.Firewall;

namespace WinSight.FirewallService;

public sealed class FirewallStorageTrustGuard : IFirewallStorageTrustGuard
{
    private readonly IServicePathTrustInspector _inspector;
    private readonly string _directory;
    private readonly string _policyFile;

    public FirewallStorageTrustGuard(
        IServicePathTrustInspector inspector,
        string directory,
        string policyFile)
    {
        _inspector = inspector ?? throw new ArgumentNullException(nameof(inspector));
        _directory = directory;
        _policyFile = policyFile;
    }

    public FirewallStorageTrustLease Inspect()
    {
        var evidence = _inspector.InspectPolicyStorageEvidence(_directory, _policyFile);
        return new(evidence.Decision.IsTrusted, evidence.Decision.Code.ToString(), evidence);
    }

    public FirewallStorageTrustLease Revalidate(FirewallStorageTrustLease lease)
    {
        if (lease.Evidence is not PathTrustEvidence evidence)
            return new(false, PathTrustCode.InspectionFailed.ToString());
        var decision = _inspector.Revalidate(evidence);
        return new(decision.IsTrusted, decision.Code.ToString(), evidence);
    }
}
