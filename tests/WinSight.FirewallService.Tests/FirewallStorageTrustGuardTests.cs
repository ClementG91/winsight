using WinSight.Firewall;
using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

/// <summary>
/// The guard is the only thing standing between privileged policy storage and the trust inspector,
/// and it had no coverage at all. These tests pin the two properties that make it a guard rather
/// than a pass-through: a lease it cannot understand must fail closed without consulting the
/// inspector, and revalidation must stay bound to the evidence captured at inspection time instead
/// of inspecting the path a second time.
/// </summary>
public sealed class FirewallStorageTrustGuardTests
{
    private const string Directory = @"C:\ProgramData\WinSight";
    private const string PolicyFile = @"C:\ProgramData\WinSight\firewall-policy.json";

    [Fact]
    public void Inspect_PassesTheDirectoryAndPolicyFileThroughUnswapped()
    {
        var inspector = new RecordingStorageInspector();
        var guard = new FirewallStorageTrustGuard(inspector, Directory, PolicyFile);

        _ = guard.Inspect();

        Assert.Equal([(Directory, PolicyFile)], inspector.InspectedPairs);
    }

    [Fact]
    public void Inspect_ReportsTrustedWithTheDecisionCode()
    {
        var inspector = new RecordingStorageInspector { Decision = PathTrustDecision.Allow() };
        var guard = new FirewallStorageTrustGuard(inspector, Directory, PolicyFile);

        var lease = guard.Inspect();

        Assert.True(lease.Trusted);
        Assert.Equal(nameof(PathTrustCode.Trusted), lease.Code);
    }

    [Theory]
    [InlineData(PathTrustCode.OutsideProgramData)]
    [InlineData(PathTrustCode.ReparsePoint)]
    [InlineData(PathTrustCode.UntrustedOwner)]
    [InlineData(PathTrustCode.WritableByUnprivilegedPrincipal)]
    [InlineData(PathTrustCode.MissingComponent)]
    [InlineData(PathTrustCode.InvalidPath)]
    [InlineData(PathTrustCode.IdentityChanged)]
    [InlineData(PathTrustCode.InspectionFailed)]
    public void Inspect_KeepsEachDenialDistinct(PathTrustCode code)
    {
        var inspector = new RecordingStorageInspector { Decision = PathTrustDecision.Deny(code) };
        var guard = new FirewallStorageTrustGuard(inspector, Directory, PolicyFile);

        var lease = guard.Inspect();

        Assert.False(lease.Trusted);
        Assert.Equal(code.ToString(), lease.Code);
    }

    [Fact]
    public void Inspect_CarriesTheEvidenceSoRevalidationCanBeBoundToIt()
    {
        var inspector = new RecordingStorageInspector();
        var guard = new FirewallStorageTrustGuard(inspector, Directory, PolicyFile);

        var lease = guard.Inspect();

        var evidence = Assert.IsType<PathTrustEvidence>(lease.Evidence);
        Assert.Same(inspector.LastEvidence, evidence);
    }

    [Fact]
    public void Revalidate_FailsClosedWhenTheLeaseCarriesNoEvidence()
    {
        var inspector = new RecordingStorageInspector();
        var guard = new FirewallStorageTrustGuard(inspector, Directory, PolicyFile);

        var lease = guard.Revalidate(new FirewallStorageTrustLease(true, "Trusted"));

        Assert.False(lease.Trusted);
        Assert.Equal(nameof(PathTrustCode.InspectionFailed), lease.Code);
        Assert.Equal(0, inspector.RevalidationCount);
    }

    [Fact]
    public void Revalidate_FailsClosedOnForeignEvidenceWithoutConsultingTheInspector()
    {
        var inspector = new RecordingStorageInspector();
        var guard = new FirewallStorageTrustGuard(inspector, Directory, PolicyFile);

        // A lease minted elsewhere, claiming trust and carrying something the guard cannot verify.
        var lease = guard.Revalidate(new FirewallStorageTrustLease(true, "Trusted", Evidence: "trust me"));

        Assert.False(lease.Trusted);
        Assert.Equal(nameof(PathTrustCode.InspectionFailed), lease.Code);
        Assert.Equal(0, inspector.RevalidationCount);
    }

    [Fact]
    public void Revalidate_ReinspectsNothingAndPassesTheOriginalEvidenceInstance()
    {
        var inspector = new RecordingStorageInspector();
        var guard = new FirewallStorageTrustGuard(inspector, Directory, PolicyFile);
        var inspected = guard.Inspect();

        _ = guard.Revalidate(inspected);

        // One inspection, from Inspect(). Revalidation must not touch the filesystem again.
        Assert.Single(inspector.InspectedPairs);
        Assert.Equal(1, inspector.RevalidationCount);
        Assert.Same(inspected.Evidence, inspector.LastRevalidated);
    }

    [Fact]
    public void Revalidate_KeepsTheEvidenceSoRepeatedRevalidationStaysBound()
    {
        var inspector = new RecordingStorageInspector();
        var guard = new FirewallStorageTrustGuard(inspector, Directory, PolicyFile);
        var inspected = guard.Inspect();

        var first = guard.Revalidate(inspected);
        var second = guard.Revalidate(first);

        Assert.True(second.Trusted);
        Assert.Same(inspected.Evidence, second.Evidence);
        Assert.Equal(2, inspector.RevalidationCount);
    }

    [Fact]
    public void Revalidate_ReportsADenialRaisedAfterInspectionSucceeded()
    {
        var inspector = new RecordingStorageInspector
        {
            RevalidateDecision = PathTrustDecision.Deny(PathTrustCode.IdentityChanged),
        };
        var guard = new FirewallStorageTrustGuard(inspector, Directory, PolicyFile);
        var inspected = guard.Inspect();

        var lease = guard.Revalidate(inspected);

        Assert.True(inspected.Trusted);
        Assert.False(lease.Trusted);
        Assert.Equal(nameof(PathTrustCode.IdentityChanged), lease.Code);
    }

    [Fact]
    public void Construction_RejectsAMissingInspector()
    {
        Assert.Throws<ArgumentNullException>(
            () => new FirewallStorageTrustGuard(null!, Directory, PolicyFile));
    }

    private sealed class RecordingStorageInspector : IServicePathTrustInspector
    {
        public PathTrustDecision Decision { get; init; } = PathTrustDecision.Allow();
        public PathTrustDecision? RevalidateDecision { get; init; }
        public List<(string Directory, string PolicyFile)> InspectedPairs { get; } = [];
        public PathTrustEvidence? LastEvidence { get; private set; }
        public PathTrustEvidence? LastRevalidated { get; private set; }
        public int RevalidationCount { get; private set; }

        public PathTrustDecision InspectExecutable(string path) =>
            throw new Xunit.Sdk.XunitException("The storage guard must not inspect executables.");

        public PathTrustDecision InspectPolicyStorage(string directory, string policyFile) =>
            InspectPolicyStorageEvidence(directory, policyFile).Decision;

        public PathTrustEvidence InspectPolicyStorageEvidence(string directory, string policyFile)
        {
            InspectedPairs.Add((directory, policyFile));
            LastEvidence = new PathTrustEvidence(
                Decision,
                policyFile,
                new Dictionary<string, string>(StringComparer.Ordinal));
            return LastEvidence;
        }

        public PathTrustDecision Revalidate(PathTrustEvidence evidence)
        {
            RevalidationCount++;
            LastRevalidated = evidence;
            return RevalidateDecision ?? evidence.Decision;
        }
    }
}
