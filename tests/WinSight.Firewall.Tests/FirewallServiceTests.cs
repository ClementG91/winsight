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

    private static FirewallRequestDispatcher Dispatcher(FirewallPolicyStore store, IOutboundFirewallEngine engine) =>
        new(store, new TestMutationAuthority(store, engine));

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
        var dispatcher = Dispatcher(new FirewallPolicyStore(PolicyPath), new AuditOnlyFirewallEngine());

        var response = await dispatcher.DispatchAsync(Request(FirewallCommand.GetStatus), callerAuthorised: false);

        Assert.False(response.Success);
        Assert.Equal(FirewallProtocolError.Unauthorized, response.Error);
        Assert.Null(response.Status);
    }

    [Fact]
    public async Task DispatchAsync_GetStatus_EmptyStore_IsAuditOnlyAndNotEnforcing()
    {
        var dispatcher = Dispatcher(new FirewallPolicyStore(PolicyPath), new AuditOnlyFirewallEngine());

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
        var dispatcher = Dispatcher(store, engine);
        var policy = new AppFirewallPolicy(@"C:\Program Files\App\app.exe", OutboundAction.Block);

        var response = await dispatcher.DispatchAsync(
            Request(FirewallCommand.UpsertPolicy, policy: policy), callerAuthorised: true);

        Assert.True(response.Success);
        Assert.Equal(0, engine.Applied);
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
        var dispatcher = Dispatcher(store, new AuditOnlyFirewallEngine());
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
    public async Task DispatchAsync_RemovePolicy_DeletesEntryWithoutMutatingEngineInAuditOnly()
    {
        var store = new FirewallPolicyStore(PolicyPath);
        var engine = new CountingEngine();
        var dispatcher = Dispatcher(store, engine);
        const string path = @"C:\Program Files\App\app.exe";
        await dispatcher.DispatchAsync(
            Request(FirewallCommand.UpsertPolicy, policy: new AppFirewallPolicy(path, OutboundAction.Block)),
            callerAuthorised: true);

        var response = await dispatcher.DispatchAsync(
            Request(FirewallCommand.RemovePolicy, executablePath: path), callerAuthorised: true);

        Assert.True(response.Success);
        Assert.Equal(0, engine.Applied);
        Assert.Equal(0, engine.Removed);
        var reloaded = await store.LoadAsync();
        Assert.Empty(reloaded.Policies);
    }

    [Fact]
    public async Task DispatchAsync_ListPolicies_PagesDeterministically()
    {
        var store = new FirewallPolicyStore(PolicyPath);
        var dispatcher = Dispatcher(store, new AuditOnlyFirewallEngine());
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
        var dispatcher = Dispatcher(store, engine);
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

    [Theory]
    [InlineData(FirewallCommand.GetStatus, true)]
    [InlineData(FirewallCommand.ListPolicies, true)]
    [InlineData(FirewallCommand.UpsertPolicy, false)]
    [InlineData(FirewallCommand.RemovePolicy, false)]
    [InlineData(FirewallCommand.EmergencyDisable, false)]
    public async Task DispatchAsync_ReadCapability_AllowsOnlyReadCommands(FirewallCommand command, bool expectedSuccess)
    {
        var store = new FirewallPolicyStore(PolicyPath);
        var dispatcher = Dispatcher(store, new CountingEngine());
        var request = command switch
        {
            FirewallCommand.ListPolicies => Request(command, offset: 0, limit: 10),
            FirewallCommand.UpsertPolicy => Request(command,
                policy: new AppFirewallPolicy(@"C:\apps\a.exe", OutboundAction.Block)),
            FirewallCommand.RemovePolicy => Request(command, executablePath: @"C:\apps\a.exe"),
            _ => Request(command),
        };

        var response = await dispatcher.DispatchAsync(request, FirewallCallerCapability.ReadStatus);

        Assert.Equal(expectedSuccess, response.Success);
        Assert.Equal(expectedSuccess ? FirewallProtocolError.None : FirewallProtocolError.Unauthorized, response.Error);
    }

    [Fact]
    public async Task DispatchAsync_UntrustedStorage_DoesNotReadWriteOrCallEngine()
    {
        Directory.CreateDirectory(_directory);
        await File.WriteAllTextAsync(PolicyPath, "attacker-controlled-content");
        var inspections = 0;
        var store = new FirewallPolicyStore(PolicyPath, storageTrust: () =>
        {
            inspections++;
            return (false, "StorageAclUntrusted");
        });
        var engine = new CountingEngine();
        var dispatcher = Dispatcher(store, engine);

        var response = await dispatcher.DispatchAsync(
            Request(FirewallCommand.UpsertPolicy,
                policy: new AppFirewallPolicy(@"C:\apps\a.exe", OutboundAction.Block)),
            FirewallCallerCapability.MutateMachinePolicy);

        Assert.False(response.Success);
        Assert.Equal(FirewallProtocolError.InternalFailure, response.Error);
        Assert.True(inspections >= 1);
        Assert.Equal("attacker-controlled-content", await File.ReadAllTextAsync(PolicyPath));
        Assert.Equal(0, engine.Applied);
        Assert.Equal(0, engine.Removed);
    }

    [Fact]
    public async Task DispatchAsync_MutationsDelegateToSingleAuthority()
    {
        var store = new FirewallPolicyStore(PolicyPath);
        var authority = new RecordingAuthority();
        var dispatcher = new FirewallRequestDispatcher(store, authority);

        Assert.True((await dispatcher.DispatchAsync(Request(FirewallCommand.UpsertPolicy,
            policy: new AppFirewallPolicy(@"C:\apps\a.exe", OutboundAction.Block)), true)).Success);
        Assert.True((await dispatcher.DispatchAsync(Request(FirewallCommand.RemovePolicy,
            executablePath: @"C:\apps\a.exe"), true)).Success);
        Assert.True((await dispatcher.DispatchAsync(Request(FirewallCommand.EnableEnforcement), true)).Success);
        Assert.True((await dispatcher.DispatchAsync(Request(FirewallCommand.EmergencyDisable), true)).Success);

        Assert.Equal(["upsert", "remove", "enable", "emergency"], authority.Calls);
    }

    // Arming the machine is a mutation: an unprivileged dashboard holds ReadStatus, which lets
    // it observe the firewall but must never let it start filtering traffic.
    [Theory]
    [InlineData(FirewallCallerCapability.ReadStatus)]
    [InlineData(FirewallCallerCapability.None)]
    public async Task DispatchAsync_EnableEnforcement_WithoutMutateCapability_IsUnauthorisedAndDoesNotArm(
        FirewallCallerCapability capability)
    {
        var authority = new RecordingAuthority();
        var dispatcher = new FirewallRequestDispatcher(new FirewallPolicyStore(PolicyPath), authority);

        var response = await dispatcher.DispatchAsync(Request(FirewallCommand.EnableEnforcement), capability);

        Assert.False(response.Success);
        Assert.Equal(FirewallProtocolError.Unauthorized, response.Error);
        Assert.Empty(authority.Calls);
    }

    // Persisting Enforcement on a machine that cannot filter would read as protection that is
    // not there, so the request is refused before the authority is ever asked.
    [Fact]
    public async Task DispatchAsync_EnableEnforcement_WithoutUsableEngine_IsNotSupportedAndDoesNotArm()
    {
        var authority = new UnsupportedEngineAuthority();
        var dispatcher = new FirewallRequestDispatcher(new FirewallPolicyStore(PolicyPath), authority);

        var response = await dispatcher.DispatchAsync(
            Request(FirewallCommand.EnableEnforcement), FirewallCallerCapability.MutateMachinePolicy);

        Assert.False(response.Success);
        Assert.Equal(FirewallProtocolError.NotSupported, response.Error);
        Assert.False(authority.EnableAttempted);
    }

    [Fact]
    public async Task DispatchAsync_EnableEnforcement_ReportsTheArmedStatusBack()
    {
        var dispatcher = new FirewallRequestDispatcher(new FirewallPolicyStore(PolicyPath), new RecordingAuthority());

        var response = await dispatcher.DispatchAsync(
            Request(FirewallCommand.EnableEnforcement), FirewallCallerCapability.MutateMachinePolicy);

        Assert.True(response.Success);
        Assert.Equal(OutboundFirewallMode.Enforcement, response.Status!.Mode);
        Assert.True(response.Status.EnforcementEnabled);
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

    private sealed class TestMutationAuthority : IFirewallMutationAuthority
    {
        private readonly FirewallPolicyStore _store;
        private readonly IOutboundFirewallEngine _engine;

        public TestMutationAuthority(FirewallPolicyStore store, IOutboundFirewallEngine engine)
        {
            _store = store;
            _engine = engine;
        }

        public bool EngineSupported => _engine.IsSupported;

        public async Task UpsertPolicyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        {
            var configuration = await _store.LoadAsync(cancellationToken);
            var policies = configuration.Policies
                .Where(item => !string.Equals(item.ExecutablePath, policy.ExecutablePath, StringComparison.OrdinalIgnoreCase))
                .Append(policy).ToArray();
            await _store.SaveAsync(configuration with { Policies = policies }, cancellationToken);
            if (configuration.Mode == OutboundFirewallMode.Enforcement) await _engine.ApplyAsync(policy, cancellationToken);
        }

        public async Task RemovePolicyAsync(string executablePath, CancellationToken cancellationToken = default)
        {
            var configuration = await _store.LoadAsync(cancellationToken);
            await _store.SaveAsync(configuration with
            {
                Policies = configuration.Policies
                    .Where(item => !string.Equals(item.ExecutablePath, executablePath, StringComparison.OrdinalIgnoreCase))
                    .ToArray(),
            }, cancellationToken);
            if (configuration.Mode == OutboundFirewallMode.Enforcement) await _engine.RemoveAsync(executablePath, cancellationToken);
        }

        public async Task<OutboundFirewallConfiguration> EnableEnforcementAsync(CancellationToken cancellationToken = default)
        {
            var configuration = await _store.LoadAsync(cancellationToken);
            var enforcing = configuration with { Mode = OutboundFirewallMode.Enforcement };
            await _store.SaveAsync(enforcing, cancellationToken);
            foreach (var policy in configuration.Policies.Where(policy => policy.Action == OutboundAction.Block))
            {
                await _engine.ApplyAsync(policy, cancellationToken);
            }
            return enforcing;
        }

        public async Task<OutboundFirewallConfiguration> EmergencyDisableAsync(CancellationToken cancellationToken = default)
        {
            var configuration = await _store.LoadAsync(cancellationToken);
            foreach (var policy in configuration.Policies) await _engine.RemoveAsync(policy.ExecutablePath, cancellationToken);
            var audit = configuration with { Mode = OutboundFirewallMode.AuditOnly };
            await _store.SaveAsync(audit, cancellationToken);
            return audit;
        }
    }

    private sealed class RecordingAuthority : IFirewallMutationAuthority
    {
        public List<string> Calls { get; } = [];
        public bool EngineSupported => true;
        public Task UpsertPolicyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        { Calls.Add("upsert"); return Task.CompletedTask; }
        public Task RemovePolicyAsync(string executablePath, CancellationToken cancellationToken = default)
        { Calls.Add("remove"); return Task.CompletedTask; }
        public Task<OutboundFirewallConfiguration> EnableEnforcementAsync(CancellationToken cancellationToken = default)
        {
            Calls.Add("enable");
            return Task.FromResult(OutboundFirewallConfiguration.Empty with { Mode = OutboundFirewallMode.Enforcement });
        }
        public Task<OutboundFirewallConfiguration> EmergencyDisableAsync(CancellationToken cancellationToken = default)
        { Calls.Add("emergency"); return Task.FromResult(OutboundFirewallConfiguration.Empty); }
    }

    private sealed class UnsupportedEngineAuthority : IFirewallMutationAuthority
    {
        public bool EnableAttempted { get; private set; }
        public bool EngineSupported => false;
        public Task UpsertPolicyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
        public Task RemovePolicyAsync(string executablePath, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
        public Task<OutboundFirewallConfiguration> EnableEnforcementAsync(CancellationToken cancellationToken = default)
        {
            EnableAttempted = true;
            return Task.FromResult(OutboundFirewallConfiguration.Empty with { Mode = OutboundFirewallMode.Enforcement });
        }
        public Task<OutboundFirewallConfiguration> EmergencyDisableAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(OutboundFirewallConfiguration.Empty);
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
        return new FirewallConnectionHandler(new FirewallRequestDispatcher(store, new ReadOnlyMutationAuthority()));
    }

    private sealed class ReadOnlyMutationAuthority : IFirewallMutationAuthority
    {
        public bool EngineSupported => false;
        public Task UpsertPolicyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task RemovePolicyAsync(string executablePath, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<OutboundFirewallConfiguration> EnableEnforcementAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<OutboundFirewallConfiguration> EmergencyDisableAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
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
    public async Task RealIdentityAuthorisation_RoundTripsOverPipe()
    {
        // Exercises the real DefaultAuthorise path (RunAsClient + IsAuthorisedCaller) with
        // the real client. This only succeeds when the client requests impersonation, so it
        // guards against the client silently connecting with an anonymous token, which the
        // service would deny and the dashboard would surface as "service unavailable".
        var pipeName = UniquePipeName();
        var server = new NamedPipeFirewallServer(
            Handler(), pipeName, securityFactory: CurrentUserSecurity);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        var serverTask = server.ServeOnceAsync(cts.Token);
        var client = new FirewallServiceClient(pipeName);
        var response = await client.SendAsync(
            new FirewallCommandRequest(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus),
            TimeSpan.FromSeconds(15),
            cts.Token);
        await serverTask;

        Assert.True(response.Success);
        Assert.Equal(FirewallProtocolError.None, response.Error);
        Assert.NotNull(response.Status);
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
