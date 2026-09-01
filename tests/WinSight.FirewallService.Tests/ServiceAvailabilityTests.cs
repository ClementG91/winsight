using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

/// <summary>
/// The two ways an unprivileged caller could keep the firewall service down.
/// </summary>
public sealed class ServiceAvailabilityTests
{
    /// <summary>
    /// A clean exit tells the Service Control Manager the stop was intentional, and
    /// SERVICE_FAILURE_ACTIONS - configured with restarts at 5 s, 30 s and then every 60 s - is only
    /// consulted when a service terminates with an error.
    /// </summary>
    /// <remarks>
    /// So the recovery path did not run: the SCM saw nothing to recover from, and the hard-exit
    /// watchdog is a background thread a normal process exit removes before its eight seconds. The
    /// concrete case is pipe squatting - a caller owning the pipe name before the service starts
    /// makes FIRST_PIPE_INSTANCE creation fail after the startup service has already applied the
    /// filters, so the squatter gets "filters applied, then immediately removed", in a loop, without
    /// privilege and with nothing restarting the service in between.
    /// </remarks>
    [Fact]
    public void AnEndpointLossExitsWithAFailureTheScmWillActOn()
    {
        var signal = new FirewallServiceExitSignal();

        signal.ReportEndpointLost();

        Assert.True(signal.EndpointLost);
        Assert.NotEqual(0, signal.ExitCode);
    }

    [Fact]
    public void AnOrdinaryShutdownStillExitsCleanly()
    {
        var signal = new FirewallServiceExitSignal();

        Assert.False(signal.EndpointLost);
        Assert.Equal(0, signal.ExitCode);
    }

    [Fact]
    public void ReportingTheLossTwiceIsIdempotent()
    {
        var signal = new FirewallServiceExitSignal();

        signal.ReportEndpointLost();
        signal.ReportEndpointLost();

        Assert.Equal(1, signal.ExitCode);
    }

    /// <summary>
    /// Installation must refuse, loudly and before registering anything, when the policy directory
    /// cannot be provisioned.
    /// </summary>
    /// <remarks>
    /// The default ACL on C:\ProgramData lets BUILTIN\Users create subdirectories and materialises
    /// CREATOR OWNER as FullControl for whoever created one, so a standard user can create
    /// C:\ProgramData\WinSight first, own it, and remove SYSTEM. The service cannot take it back -
    /// its token holds neither SeTakeOwnership nor SeRestore by design - so it fails on every boot
    /// and looks to the operator exactly like a machine where nothing was ever installed. Install
    /// runs elevated and can reclaim the directory, which is why the work belongs here.
    /// </remarks>
    [Fact]
    public void InstallRefusesBeforeRegisteringWhenPolicyStorageCannotBeProvisioned()
    {
        var scm = new RecordingServiceControlManager();

        var failure = Assert.Throws<ServiceInstallTrustException>(() =>
            FirewallServiceInstaller.Install(
                @"C:\trusted\service.exe",
                new AlwaysTrustedInspector(),
                scm,
                static () => throw new UnauthorizedAccessException("squatted")));

        Assert.Equal(ServiceInstallTrustCode.PolicyStorageRefused, failure.Code);
        Assert.False(scm.CreateCalled, "nothing may be registered once storage is known to be unusable");
    }

    [Fact]
    public void InstallProceedsWhenPolicyStorageProvisions()
    {
        var scm = new RecordingServiceControlManager();

        FirewallServiceInstaller.Install(
            @"C:\trusted\service.exe", new AlwaysTrustedInspector(), scm, static () => { });

        Assert.True(scm.CreateCalled);
    }

    private sealed class AlwaysTrustedInspector : IServicePathTrustInspector
    {
        public PathTrustDecision InspectExecutable(string path) => PathTrustDecision.Allow();

        public PathTrustDecision InspectPolicyStorage(string directory, string policyFile) =>
            PathTrustDecision.Allow();

        public PathTrustDecision Revalidate(PathTrustEvidence evidence) => PathTrustDecision.Allow();
    }

    private sealed class RecordingServiceControlManager : IServiceControlManager
    {
        internal bool CreateCalled { get; private set; }

        public IServiceRegistration Create(string binaryPath)
        {
            CreateCalled = true;
            return new NoOpRegistration();
        }

        public IServiceRegistration OpenForRemoval() => new NoOpRegistration();

        private sealed class NoOpRegistration : IServiceRegistration
        {
            public void SetDescription(string description)
            {
            }

            public void ConfigureSecurityProfile()
            {
            }

            public void StopAndWait(TimeSpan timeout)
            {
            }

            public bool Delete() => true;

            public void Dispose()
            {
            }
        }
    }
}
