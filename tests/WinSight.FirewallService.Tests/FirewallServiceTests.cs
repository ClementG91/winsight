using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using WinSight.Firewall;
using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

public sealed class FirewallServiceWorkerTests
{
    [Fact]
    public async Task Worker_RunsListenerUntilStopped()
    {
        var listener = new BlockingListener();
        using var worker = new FirewallServiceWorker(listener, NullLogger<FirewallServiceWorker>.Instance);

        await worker.StartAsync(CancellationToken.None);
        await listener.Started.WaitAsync(TimeSpan.FromSeconds(5));

        // The listener is still running until the host stops the worker.
        Assert.False(listener.Completed);

        await worker.StopAsync(CancellationToken.None);
        Assert.True(listener.WasCancelled);
    }

    [Fact]
    public async Task Worker_StopsCleanly_WhenListenerCompletesOnItsOwn()
    {
        var listener = new SignalingListener();
        using var worker = new FirewallServiceWorker(listener, NullLogger<FirewallServiceWorker>.Instance);

        await worker.StartAsync(CancellationToken.None);
        // Await the signal rather than a plain field, so completion is observed
        // deterministically regardless of which thread ran ExecuteAsync.
        await listener.Ran.WaitAsync(TimeSpan.FromSeconds(5));
        await worker.StopAsync(CancellationToken.None);
    }

    private sealed class BlockingListener : IFirewallServiceListener
    {
        private readonly TaskCompletionSource _started =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task Started => _started.Task;

        public bool Completed { get; private set; }

        public bool WasCancelled { get; private set; }

        public async Task RunAsync(CancellationToken cancellationToken)
        {
            _started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                WasCancelled = true;
                throw;
            }
            finally
            {
                Completed = true;
            }
        }
    }

    private sealed class SignalingListener : IFirewallServiceListener
    {
        private readonly TaskCompletionSource _ran =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task Ran => _ran.Task;

        public Task RunAsync(CancellationToken cancellationToken)
        {
            _ran.TrySetResult();
            return Task.CompletedTask;
        }
    }
}

public sealed class FirewallServicePathsTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"winsight-fw-svc-paths-{Guid.NewGuid():N}");

    [Fact]
    public void CreateHardenedDirectorySecurity_GrantsOnlyTrustedPrincipals_AndIsProtected()
    {
        var security = FirewallServicePaths.CreateHardenedDirectorySecurity();

        Assert.True(security.AreAccessRulesProtected);
        var rules = security
            .GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToList();

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

        Assert.Contains(rules, r => r.IdentityReference.Equals(system)
            && r.FileSystemRights.HasFlag(FileSystemRights.FullControl)
            && r.AccessControlType == AccessControlType.Allow);
        Assert.Contains(rules, r => r.IdentityReference.Equals(administrators)
            && r.AccessControlType == AccessControlType.Allow);
        Assert.DoesNotContain(rules, r => r.IdentityReference.Equals(everyone));
    }

    [Fact]
    public void ProvisionDirectory_CreatesDirectory_WithProtectedAcl()
    {
        var provisioned = FirewallServicePaths.ProvisionDirectory(_directory);

        Assert.True(Directory.Exists(provisioned));
        var security = new DirectoryInfo(provisioned).GetAccessControl();
        Assert.True(security.AreAccessRulesProtected);
    }

    [Fact]
    public void DefaultPolicyFile_IsUnderProgramData()
    {
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        Assert.StartsWith(programData, FirewallServicePaths.DefaultPolicyFile, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith("policies.json", FirewallServicePaths.DefaultPolicyFile, StringComparison.OrdinalIgnoreCase);
    }

    public void Dispose()
    {
        if (!Directory.Exists(_directory))
        {
            return;
        }

        // The hardened ACL locks out the (non-admin) test user, but the creator remains
        // the owner and can always rewrite the DACL. Restore access before cleaning up.
        try
        {
            var info = new DirectoryInfo(_directory);
            var security = info.GetAccessControl();
            security.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
            using var current = WindowsIdentity.GetCurrent();
            security.AddAccessRule(new FileSystemAccessRule(
                current.User!, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
            info.SetAccessControl(security);
            Directory.Delete(_directory, recursive: true);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            // Best-effort cleanup of a temp directory; leave it to the OS otherwise.
        }
    }
}
