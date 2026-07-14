using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using WinSight.Firewall;
using Xunit;

namespace WinSight.Firewall.Tests;

public sealed class FirewallRequestDispatcherTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"winsight-fw-service-{Guid.NewGuid():N}");

    private string PolicyPath => Path.Combine(_directory, "policies.json");

    private static FirewallCommandRequest Request(
        FirewallCommand command,
        AppFirewallPolicy? policy = null,
        string? executablePath = null,
        int? offset = null,
        int? limit = null) =>
        new(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), command, policy, executablePath, offset, limit);

    [Fact]
    public async Task DispatchAsync_UnauthorisedCaller_IsAlwaysRejected()
    {
        var dispatcher = new FirewallRequestDispatcher(new FirewallPolicyStore(PolicyPath), new AuditOnlyFirewallEngine());

        var response = await dispatcher.DispatchAsync(Request(FirewallCommand.GetStatus), callerAuthorised: false);

        Assert.False(response.Success);
        Assert.Equal(FirewallProtocolError.Unauthorized, response.Error);
        Assert.Null(response.Status);
    }

    [Fact]
    public async Task DispatchAsync_GetStatus_EmptyStore_IsAuditOnlyAndNotEnforcing()
    {
        var dispatcher = new FirewallRequestDispatcher(new FirewallPolicyStore(PolicyPath), new AuditOnlyFirewallEngine());

        var response = await dispatcher.DispatchAsync(Request(FirewallCommand.GetStatus), callerAuthorised: true);

        Assert.True(response.Success);
        Assert.NotNull(response.Status);
        Assert.Equal(OutboundFirewallMode.AuditOnly, response.Status!.Mode);
        Assert.False(response.Status.EngineSupported);
        Assert.False(response.Status.EnforcementEnabled);
    }

    [Fact]
    public async Task DispatchAsync_UpsertPolicy_PersistsAndStaysAuditOnly()
    {
        var store = new FirewallPolicyStore(PolicyPath);
        var engine = new CountingEngine();
        var dispatcher = new FirewallRequestDispatcher(store, engine);
        var policy = new AppFirewallPolicy(@"C:\Program Files\App\app.exe", OutboundAction.Block);

        var response = await dispatcher.DispatchAsync(
            Request(FirewallCommand.UpsertPolicy, policy: policy), callerAuthorised: true);

        Assert.True(response.Success);
        Assert.Equal(1, engine.Applied);
        var reloaded = await store.LoadAsync();
        Assert.Equal(OutboundFirewallMode.AuditOnly, reloaded.Mode);
        var stored = Assert.Single(reloaded.Policies);
        Assert.Equal(OutboundAction.Block, stored.Action);
        Assert.EndsWith("app.exe", stored.ExecutablePath, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DispatchAsync_UpsertPolicy_SamePath_ReplacesInsteadOfDuplicating()
    {
        var store = new FirewallPolicyStore(PolicyPath);
        var dispatcher = new FirewallRequestDispatcher(store, new AuditOnlyFirewallEngine());
        const string path = @"C:\Program Files\App\app.exe";

        await dispatcher.DispatchAsync(
            Request(FirewallCommand.UpsertPolicy, policy: new AppFirewallPolicy(path, OutboundAction.Allow)),
            callerAuthorised: true);
        await dispatcher.DispatchAsync(
            Request(FirewallCommand.UpsertPolicy, policy: new AppFirewallPolicy(path, OutboundAction.Block)),
            callerAuthorised: true);

        var reloaded = await store.LoadAsync();
        var stored = Assert.Single(reloaded.Policies);
        Assert.Equal(OutboundAction.Block, stored.Action);
    }

    [Fact]
    public async Task DispatchAsync_RemovePolicy_DeletesEntryAndNotifiesEngine()
    {
        var store = new FirewallPolicyStore(PolicyPath);
        var engine = new CountingEngine();
        var dispatcher = new FirewallRequestDispatcher(store, engine);
        const string path = @"C:\Program Files\App\app.exe";
        await dispatcher.DispatchAsync(
            Request(FirewallCommand.UpsertPolicy, policy: new AppFirewallPolicy(path, OutboundAction.Block)),
            callerAuthorised: true);

        var response = await dispatcher.DispatchAsync(
            Request(FirewallCommand.RemovePolicy, executablePath: path), callerAuthorised: true);

        Assert.True(response.Success);
        Assert.True(engine.Removed >= 1);
        var reloaded = await store.LoadAsync();
        Assert.Empty(reloaded.Policies);
    }

    [Fact]
    public async Task DispatchAsync_ListPolicies_PagesDeterministically()
    {
        var store = new FirewallPolicyStore(PolicyPath);
        var dispatcher = new FirewallRequestDispatcher(store, new AuditOnlyFirewallEngine());
        foreach (var name in new[] { "c.exe", "a.exe", "b.exe" })
        {
            await dispatcher.DispatchAsync(
                Request(FirewallCommand.UpsertPolicy, policy: new AppFirewallPolicy($@"C:\apps\{name}", OutboundAction.Ask)),
                callerAuthorised: true);
        }

        var firstPage = await dispatcher.DispatchAsync(
            Request(FirewallCommand.ListPolicies, offset: 0, limit: 2), callerAuthorised: true);
        var secondPage = await dispatcher.DispatchAsync(
            Request(FirewallCommand.ListPolicies, offset: 2, limit: 2), callerAuthorised: true);

        Assert.True(firstPage.Success);
        Assert.Equal(2, firstPage.Policies!.Length);
        Assert.Equal(2, firstPage.NextOffset);
        Assert.EndsWith("a.exe", firstPage.Policies[0].ExecutablePath, StringComparison.OrdinalIgnoreCase);
        Assert.Single(secondPage.Policies!);
        Assert.Null(secondPage.NextOffset);
    }

    [Fact]
    public async Task DispatchAsync_EmergencyDisable_ReturnsToAuditOnlyAndClearsEngine()
    {
        var store = new FirewallPolicyStore(PolicyPath);
        var engine = new CountingEngine();
        var dispatcher = new FirewallRequestDispatcher(store, engine);
        foreach (var name in new[] { "a.exe", "b.exe" })
        {
            await dispatcher.DispatchAsync(
                Request(FirewallCommand.UpsertPolicy, policy: new AppFirewallPolicy($@"C:\apps\{name}", OutboundAction.Block)),
                callerAuthorised: true);
        }

        var response = await dispatcher.DispatchAsync(Request(FirewallCommand.EmergencyDisable), callerAuthorised: true);

        Assert.True(response.Success);
        Assert.NotNull(response.Status);
        Assert.Equal(OutboundFirewallMode.AuditOnly, response.Status!.Mode);
        Assert.Equal(2, engine.Removed);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private sealed class CountingEngine : IOutboundFirewallEngine
    {
        public int Applied { get; private set; }

        public int Removed { get; private set; }

        public bool IsSupported => false;

        public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        {
            Applied++;
            return Task.CompletedTask;
        }

        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default)
        {
            Removed++;
            return Task.CompletedTask;
        }
    }
}

public sealed class FirewallServiceSecurityTests
{
    [Fact]
    public void CreateHardenedSecurity_GrantsTrustedPrincipals_AndDeniesNetwork()
    {
        var security = FirewallServiceSecurity.CreateHardenedSecurity();
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
            .Cast<PipeAccessRule>()
            .ToList();

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var network = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);

        Assert.Contains(rules, r =>
            r.IdentityReference.Equals(system) && r.AccessControlType == AccessControlType.Allow);
        Assert.Contains(rules, r =>
            r.IdentityReference.Equals(administrators) && r.AccessControlType == AccessControlType.Allow);
        Assert.Contains(rules, r =>
            r.IdentityReference.Equals(network) && r.AccessControlType == AccessControlType.Deny);
    }

    [Fact]
    public void IsAuthorisedCaller_NullIdentity_IsFalse() =>
        Assert.False(FirewallServiceSecurity.IsAuthorisedCaller(null));

    [Fact]
    public void IsAuthorisedCaller_CurrentIdentity_IsTrue()
    {
        using var identity = WindowsIdentity.GetCurrent();
        Assert.True(FirewallServiceSecurity.IsAuthorisedCaller(identity));
    }
}

public sealed class NamedPipeFirewallServerTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"winsight-fw-pipe-{Guid.NewGuid():N}");

    private static string UniquePipeName() => $"WinSight\\test-{Guid.NewGuid():N}";

    // A current-user ACL so the exchange is exercised on non-interactive CI runners,
    // whose token may lack the Interactive SID the hardened production ACL grants.
    private static PipeSecurity CurrentUserSecurity()
    {
        var security = new PipeSecurity();
        using var identity = WindowsIdentity.GetCurrent();
        security.AddAccessRule(new PipeAccessRule(
            identity.User!, PipeAccessRights.FullControl, AccessControlType.Allow));
        return security;
    }

    private FirewallConnectionHandler Handler()
    {
        var store = new FirewallPolicyStore(Path.Combine(_directory, "policies.json"));
        return new FirewallConnectionHandler(new FirewallRequestDispatcher(store, new AuditOnlyFirewallEngine()));
    }

    [Fact]
    public async Task AuthorisedClient_GetStatus_RoundTripsOverPipe()
    {
        var pipeName = UniquePipeName();
        var server = new NamedPipeFirewallServer(
            Handler(), pipeName, authorise: _ => true, securityFactory: CurrentUserSecurity);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        var serverTask = server.ServeOnceAsync(cts.Token);
        var client = new FirewallServiceClient(pipeName);
        var response = await client.SendAsync(
            new FirewallCommandRequest(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus),
            TimeSpan.FromSeconds(15),
            cts.Token);
        await serverTask;

        Assert.True(response.Success);
        Assert.Equal(OutboundFirewallMode.AuditOnly, response.Status!.Mode);
    }

    [Fact]
    public async Task UnauthorisedClient_ReceivesUnauthorized()
    {
        var pipeName = UniquePipeName();
        var server = new NamedPipeFirewallServer(
            Handler(), pipeName, authorise: _ => false, securityFactory: CurrentUserSecurity);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        var serverTask = server.ServeOnceAsync(cts.Token);
        var client = new FirewallServiceClient(pipeName);
        var response = await client.SendAsync(
            new FirewallCommandRequest(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus),
            TimeSpan.FromSeconds(15),
            cts.Token);
        await serverTask;

        Assert.False(response.Success);
        Assert.Equal(FirewallProtocolError.Unauthorized, response.Error);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}
