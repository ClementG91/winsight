using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
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
        int? limit = null,
        string? snapshotVersion = null) =>
        new(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), command, policy, executablePath, offset, limit,
            snapshotVersion);

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
            Request(FirewallCommand.ListPolicies, offset: 2, limit: 2,
                snapshotVersion: firstPage.SnapshotVersion), callerAuthorised: true);

        Assert.True(firstPage.Success);
        Assert.Equal(2, firstPage.Policies!.Length);
        Assert.Equal(2, firstPage.NextOffset);
        Assert.EndsWith("a.exe", firstPage.Policies[0].ExecutablePath, StringComparison.OrdinalIgnoreCase);
        Assert.Single(secondPage.Policies!);
        Assert.Null(secondPage.NextOffset);
        Assert.Equal(firstPage.SnapshotVersion, secondPage.SnapshotVersion);
        Assert.Equal(3, firstPage.SnapshotCount);
        Assert.Equal(3, secondPage.SnapshotCount);
    }

    [Theory]
    [InlineData("insert")]
    [InlineData("delete")]
    [InlineData("update")]
    public async Task DispatchAsync_PolicyMutationBetweenPages_ReturnsSnapshotChanged(string mutation)
    {
        var store = new FirewallPolicyStore(PolicyPath);
        var dispatcher = Dispatcher(store, new AuditOnlyFirewallEngine());
        foreach (var name in new[] { "a.exe", "b.exe", "c.exe" })
        {
            await dispatcher.DispatchAsync(
                Request(FirewallCommand.UpsertPolicy,
                    policy: new AppFirewallPolicy($@"C:\apps\{name}", OutboundAction.Ask)),
                callerAuthorised: true);
        }
        var first = await dispatcher.DispatchAsync(
            Request(FirewallCommand.ListPolicies, offset: 0, limit: 1), callerAuthorised: true);

        var mutationRequest = mutation switch
        {
            "insert" => Request(FirewallCommand.UpsertPolicy,
                policy: new AppFirewallPolicy(@"C:\apps\aa.exe", OutboundAction.Block)),
            "delete" => Request(FirewallCommand.RemovePolicy, executablePath: @"C:\apps\a.exe"),
            _ => Request(FirewallCommand.UpsertPolicy,
                policy: new AppFirewallPolicy(@"C:\apps\a.exe", OutboundAction.Block)),
        };
        Assert.True((await dispatcher.DispatchAsync(mutationRequest, callerAuthorised: true)).Success);

        var continuation = await dispatcher.DispatchAsync(
            Request(FirewallCommand.ListPolicies, offset: 1, limit: 1,
                snapshotVersion: first.SnapshotVersion), callerAuthorised: true);

        Assert.False(continuation.Success);
        Assert.Equal(FirewallProtocolError.SnapshotChanged, continuation.Error);
        Assert.Null(continuation.Policies);
        Assert.Null(continuation.NextOffset);
        Assert.Null(continuation.SnapshotVersion);
        Assert.Null(continuation.SnapshotCount);
    }

    [Theory]
    [InlineData("insert")]
    [InlineData("delete")]
    [InlineData("update")]
    [InlineData("policy-suppression")]
    public async Task DispatchAsync_PendingMutationBetweenPages_ReturnsSnapshotChanged(string mutation)
    {
        var pending = new PendingOutboundLog();
        var now = DateTimeOffset.UnixEpoch;
        pending.Observe(@"C:\apps\a.exe", "1.2.3.4:443", now);
        pending.Observe(@"C:\apps\b.exe", "1.2.3.4:443", now.AddSeconds(1));
        pending.Observe(@"C:\apps\c.exe", "1.2.3.4:443", now.AddSeconds(2));
        var dispatcher = new FirewallRequestDispatcher(
            new FirewallPolicyStore(PolicyPath), new RecordingAuthority(), pending);
        var first = await dispatcher.DispatchAsync(
            Request(FirewallCommand.ListPending, offset: 0, limit: 1),
            FirewallCallerCapability.ReadStatus);

        switch (mutation)
        {
            case "insert":
                pending.Observe(@"C:\apps\d.exe", "1.2.3.4:443", now.AddSeconds(3));
                break;
            case "delete":
                pending.Resolve(@"C:\apps\a.exe");
                break;
            case "update":
                pending.Observe(@"C:\apps\a.exe", "5.6.7.8:53", now.AddSeconds(4));
                break;
            default:
                await dispatcher.DispatchAsync(
                    Request(FirewallCommand.UpsertPolicy,
                        policy: new AppFirewallPolicy(@"C:\apps\a.exe", OutboundAction.Allow)),
                    FirewallCallerCapability.MutateMachinePolicy);
                break;
        }

        var continuation = await dispatcher.DispatchAsync(
            Request(FirewallCommand.ListPending, offset: 1, limit: 1,
                snapshotVersion: first.SnapshotVersion),
            FirewallCallerCapability.ReadStatus);

        Assert.False(continuation.Success);
        Assert.Equal(FirewallProtocolError.SnapshotChanged, continuation.Error);
        Assert.Null(continuation.Pending);
        Assert.Null(continuation.NextOffset);
    }

    [Fact]
    public async Task DispatchAsync_PolicyAndPendingSnapshotsAreDeterministicAndDomainSeparated()
    {
        var path = @"C:\apps\same.exe";
        var store = new FirewallPolicyStore(PolicyPath);
        await store.SaveAsync(new OutboundFirewallConfiguration(
            OutboundFirewallMode.AuditOnly,
            [new AppFirewallPolicy(path, OutboundAction.Ask)]));
        var pending = new PendingOutboundLog();
        pending.Observe(path, "1.2.3.4:443", DateTimeOffset.UnixEpoch);
        var dispatcher = new FirewallRequestDispatcher(store, new RecordingAuthority(), pending);

        var policyA = await dispatcher.DispatchAsync(
            Request(FirewallCommand.ListPolicies, offset: 0, limit: 1),
            FirewallCallerCapability.ReadStatus);
        var policyB = await dispatcher.DispatchAsync(
            Request(FirewallCommand.ListPolicies, offset: 0, limit: 1),
            FirewallCallerCapability.ReadStatus);
        // Use a separate empty store so the pending item is not suppressed by the policy.
        var pendingDispatcher = new FirewallRequestDispatcher(
            new FirewallPolicyStore(Path.Combine(_directory, "pending-policy.json")),
            new RecordingAuthority(), pending);
        var pendingPage = await pendingDispatcher.DispatchAsync(
            Request(FirewallCommand.ListPending, offset: 0, limit: 1),
            FirewallCallerCapability.ReadStatus);

        Assert.Equal(policyA.SnapshotVersion, policyB.SnapshotVersion);
        Assert.Equal(policyA.SnapshotCount, policyB.SnapshotCount);
        Assert.NotEqual(policyA.SnapshotVersion, pendingPage.SnapshotVersion);
        Assert.True(FirewallProtocolCodec.IsSnapshotVersion(policyA.SnapshotVersion));
        Assert.True(FirewallProtocolCodec.IsSnapshotVersion(pendingPage.SnapshotVersion));
    }

    [Theory]
    [InlineData(FirewallProtocolCodec.LegacyVersion)]
    [InlineData(FirewallProtocolCodec.RuntimeProofVersion)]
    public async Task DispatchAsync_LegacyListsReturnOneCompletePageOrNotSupported(int version)
    {
        var store = new FirewallPolicyStore(PolicyPath);
        await store.SaveAsync(new OutboundFirewallConfiguration(
            OutboundFirewallMode.AuditOnly,
            [
                new AppFirewallPolicy(@"C:\apps\a.exe", OutboundAction.Ask),
                new AppFirewallPolicy(@"C:\apps\b.exe", OutboundAction.Ask),
            ]));
        var dispatcher = Dispatcher(store, new AuditOnlyFirewallEngine());
        var request = Request(FirewallCommand.ListPolicies, offset: 0, limit: 2) with
        {
            ProtocolVersion = version,
        };

        var complete = await dispatcher.DispatchAsync(request, FirewallCallerCapability.ReadStatus);
        var incomplete = await dispatcher.DispatchAsync(request with { Limit = 1 },
            FirewallCallerCapability.ReadStatus);

        Assert.True(complete.Success);
        Assert.Equal(2, complete.Policies!.Length);
        Assert.Null(complete.NextOffset);
        Assert.Null(complete.SnapshotVersion);
        Assert.Null(complete.SnapshotCount);
        Assert.False(incomplete.Success);
        Assert.Equal(FirewallProtocolError.NotSupported, incomplete.Error);
        Assert.Null(incomplete.Policies);
        Assert.Null(incomplete.NextOffset);
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

    // Observing is not mutating: an unprivileged dashboard must be able to see what reached the
    // network, which is the whole point of telling the operator about it.
    [Fact]
    public async Task DispatchAsync_ListPending_IsAvailableToAReadOnlyCaller()
    {
        var pending = new PendingOutboundLog();
        pending.Observe(@"C:\apps\unknown.exe", "1.2.3.4:443", DateTimeOffset.UtcNow);
        var dispatcher = new FirewallRequestDispatcher(
            new FirewallPolicyStore(PolicyPath), new RecordingAuthority(), pending);

        var response = await dispatcher.DispatchAsync(
            Request(FirewallCommand.ListPending, offset: 0, limit: 128), FirewallCallerCapability.ReadStatus);

        Assert.True(response.Success);
        var app = Assert.Single(response.Pending!);
        Assert.Equal(@"C:\apps\unknown.exe", app.ExecutablePath);
    }

    // An app the operator already ruled on must never be offered back as a fresh decision.
    [Fact]
    public async Task DispatchAsync_ListPending_HidesAnAppThatAlreadyHasAPolicy()
    {
        var store = new FirewallPolicyStore(PolicyPath);
        await store.SaveAsync(OutboundFirewallConfiguration.Empty with
        {
            Policies = [new AppFirewallPolicy(@"C:\apps\ruled.exe", OutboundAction.Allow)],
        });
        var pending = new PendingOutboundLog();
        pending.Observe(@"C:\apps\ruled.exe", "1.2.3.4:443", DateTimeOffset.UtcNow);
        pending.Observe(@"C:\apps\unknown.exe", "1.2.3.4:443", DateTimeOffset.UtcNow);
        var dispatcher = new FirewallRequestDispatcher(store, new RecordingAuthority(), pending);

        var response = await dispatcher.DispatchAsync(
            Request(FirewallCommand.ListPending, offset: 0, limit: 128), FirewallCallerCapability.ReadStatus);

        var app = Assert.Single(response.Pending!);
        Assert.Equal(@"C:\apps\unknown.exe", app.ExecutablePath);
    }

    // Deciding must take the app off the list at once, not leave it there until the observer's
    // snapshot goes stale and offers the operator a decision they just took.
    [Fact]
    public async Task DispatchAsync_UpsertPolicy_StopsTheAppFromBeingPending()
    {
        var pending = new PendingOutboundLog();
        pending.Observe(@"C:\apps\a.exe", "1.2.3.4:443", DateTimeOffset.UtcNow);
        var dispatcher = new FirewallRequestDispatcher(
            new FirewallPolicyStore(PolicyPath), new RecordingAuthority(), pending);

        await dispatcher.DispatchAsync(Request(FirewallCommand.UpsertPolicy,
            policy: new AppFirewallPolicy(@"c:\APPS\A.EXE", OutboundAction.Block)),
            FirewallCallerCapability.MutateMachinePolicy);

        Assert.Empty(pending.Snapshot());
    }

    [Fact]
    public async Task DispatchAsync_ListPending_PagesLikeThePolicyList()
    {
        var pending = new PendingOutboundLog();
        var start = DateTimeOffset.UtcNow;
        for (var i = 0; i < 5; i++)
        {
            pending.Observe($@"C:\apps\a{i}.exe", "1.2.3.4:443", start.AddSeconds(i));
        }
        var dispatcher = new FirewallRequestDispatcher(
            new FirewallPolicyStore(PolicyPath), new RecordingAuthority(), pending);

        var first = await dispatcher.DispatchAsync(
            Request(FirewallCommand.ListPending, offset: 0, limit: 2), FirewallCallerCapability.ReadStatus);
        Assert.Equal(2, first.Pending!.Length);
        Assert.Equal(2, first.NextOffset);

        var last = await dispatcher.DispatchAsync(
            Request(FirewallCommand.ListPending, offset: 4, limit: 2,
                snapshotVersion: first.SnapshotVersion), FirewallCallerCapability.ReadStatus);
        Assert.Single(last.Pending!);
        Assert.Null(last.NextOffset);
    }

    // The blind spot has to stay visible, or a truncated list reads as a complete one.
    [Fact]
    public async Task DispatchAsync_GetStatus_ReportsWhatTheObserverCouldNotRecord()
    {
        var pending = new PendingOutboundLog();
        for (var i = 0; i < PendingOutboundLog.MaxPendingApps + 3; i++)
        {
            pending.Observe($@"C:\apps\a{i}.exe", "1.2.3.4:443", DateTimeOffset.UtcNow);
        }
        var dispatcher = new FirewallRequestDispatcher(
            new FirewallPolicyStore(PolicyPath), new RecordingAuthority(), pending);

        var response = await dispatcher.DispatchAsync(
            Request(FirewallCommand.GetStatus), FirewallCallerCapability.ReadStatus);

        Assert.Equal(3, response.Status!.UnrecordedApps);
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
        public FirewallEnforcementState EffectiveState { get; private set; } = FirewallEnforcementState.AuditOnly;
        public Task<FirewallRuntimeStatus> GetRuntimeStatusAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new FirewallRuntimeStatus(
                EffectiveState == FirewallEnforcementState.Active
                    ? OutboundFirewallMode.Enforcement
                    : OutboundFirewallMode.AuditOnly,
                EngineSupported,
                EffectiveState));
        public Task UpsertPolicyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        { Calls.Add("upsert"); return Task.CompletedTask; }
        public Task RemovePolicyAsync(string executablePath, CancellationToken cancellationToken = default)
        { Calls.Add("remove"); return Task.CompletedTask; }
        public Task<OutboundFirewallConfiguration> EnableEnforcementAsync(CancellationToken cancellationToken = default)
        {
            Calls.Add("enable");
            EffectiveState = FirewallEnforcementState.Active;
            return Task.FromResult(OutboundFirewallConfiguration.Empty with { Mode = OutboundFirewallMode.Enforcement });
        }
        public Task<OutboundFirewallConfiguration> EmergencyDisableAsync(CancellationToken cancellationToken = default)
        {
            Calls.Add("emergency");
            EffectiveState = FirewallEnforcementState.AuditOnly;
            return Task.FromResult(OutboundFirewallConfiguration.Empty);
        }
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
        var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
        var network = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);

        Assert.Equal(system, security.GetOwner(typeof(SecurityIdentifier)));
        Assert.Contains(rules, r =>
            r.IdentityReference.Equals(system) && r.AccessControlType == AccessControlType.Allow);
        Assert.Contains(rules, r =>
            r.IdentityReference.Equals(administrators) && r.AccessControlType == AccessControlType.Allow);
        Assert.Contains(rules, r =>
            r.IdentityReference.Equals(network) && r.AccessControlType == AccessControlType.Deny);
        var interactiveRule = Assert.Single(rules, r =>
            r.IdentityReference.Equals(interactive) && r.AccessControlType == AccessControlType.Allow);
        Assert.False(interactiveRule.PipeAccessRights.HasFlag(PipeAccessRights.CreateNewInstance));
    }

    // The GrantsTrustedPrincipals test above uses Assert.Contains, which is satisfied even if a
    // broad allow ACE is ALSO present. That is the exact audit motif: a widened pipe ACL - Everyone,
    // Anonymous, Authenticated Users - would let every existing assertion still pass while opening the
    // control channel to any local account. This pins the allow-list closed: the only allowed
    // principals are SYSTEM, Administrators and Interactive, and nothing else.
    [Fact]
    public void CreateHardenedSecurity_AllowsOnlyThreeTrustedPrincipals()
    {
        var security = FirewallServiceSecurity.CreateHardenedSecurity();
        var allowed = security
            .GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
            .Cast<PipeAccessRule>()
            .Where(rule => rule.AccessControlType == AccessControlType.Allow)
            .Select(rule => (SecurityIdentifier)rule.IdentityReference)
            .ToList();

        var permitted = new[]
        {
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
        };

        var unexpected = allowed.Where(sid => !permitted.Contains(sid)).ToList();
        Assert.True(
            unexpected.Count == 0,
            "The pipe ACL grants an unexpected principal: " + string.Join(", ", unexpected));
    }

    [Fact]
    public void CreateHardenedSecurity_DoesNotGrantWorldOrAnonymous()
    {
        var security = FirewallServiceSecurity.CreateHardenedSecurity();
        var allowed = security
            .GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
            .Cast<PipeAccessRule>()
            .Where(rule => rule.AccessControlType == AccessControlType.Allow)
            .Select(rule => (SecurityIdentifier)rule.IdentityReference)
            .ToList();

        foreach (var forbidden in new[]
        {
            WellKnownSidType.WorldSid,
            WellKnownSidType.AnonymousSid,
            WellKnownSidType.AuthenticatedUserSid,
            WellKnownSidType.NetworkSid,
        })
        {
            var sid = new SecurityIdentifier(forbidden, null);
            Assert.DoesNotContain(sid, allowed);
        }
    }

    [Fact]
    public void GetCallerCapability_NullIdentity_IsNone() =>
        Assert.Equal(FirewallCallerCapability.None, FirewallServiceSecurity.GetCallerCapability(null));

    [Fact]
    public void IsAuthorisedCaller_NullIdentity_IsFalse() =>
        Assert.False(FirewallServiceSecurity.IsAuthorisedCaller(null));

    [Fact]
    public void IsAuthorisedCaller_CurrentIdentity_IsTrue()
    {
        using var identity = WindowsIdentity.GetCurrent();
        Assert.True(FirewallServiceSecurity.IsAuthorisedCaller(identity));
    }

    // The current identity is a real, authenticated, local, non-anonymous account, so it must map to
    // a real capability - and to exactly the one its elevation earns. An admin (elevated test host)
    // gets MutateMachinePolicy; a standard user gets ReadStatus. Either way it is never None, which
    // is the fail-closed sentinel reserved for identities that cannot be trusted at all.
    [Fact]
    public void GetCallerCapability_CurrentIdentity_MatchesItsElevation()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var isAdministrator = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);

        var capability = FirewallServiceSecurity.GetCallerCapability(identity);

        Assert.NotEqual(FirewallCallerCapability.None, capability);
        Assert.Equal(
            isAdministrator ? FirewallCallerCapability.MutateMachinePolicy : FirewallCallerCapability.ReadStatus,
            capability);
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
        security.SetOwner(identity.User!);
        security.AddAccessRule(new PipeAccessRule(
            identity.User!, PipeAccessRights.FullControl, AccessControlType.Allow));
        return security;
    }

    private static FirewallServiceClient TrustedTestClient(string pipeName) =>
        new(pipeName, _ => { });

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
    public void PublicConstructor_PreservesTheHistoricalSevenParameterContract()
    {
        var constructor = Assert.Single(typeof(NamedPipeFirewallServer).GetConstructors(
            BindingFlags.Instance | BindingFlags.Public));
        var parameters = constructor.GetParameters();

        Assert.Equal(7, parameters.Length);
        Assert.Equal(
        [
            typeof(FirewallConnectionHandler),
            typeof(string),
            typeof(Func<NamedPipeServerStream, bool>),
            typeof(Func<PipeSecurity>),
            typeof(Func<NamedPipeServerStream, FirewallCallerCapability>),
            typeof(TimeSpan?),
            typeof(TimeSpan?),
        ], parameters.Select(parameter => parameter.ParameterType));
        Assert.DoesNotContain(parameters, parameter =>
            string.Equals(parameter.Name, "maxServerInstances", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0, 2)]
    [InlineData(1, 1)]
    [InlineData(252, 2)]
    public void InternalConstructor_RejectsAdmissionBoundsThatCannotReserveTheHandoffInstance(
        int readCapacity, int mutationCapacity)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new NamedPipeFirewallServer(
            Handler(), UniquePipeName(), _ => true, CurrentUserSecurity, null,
            TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1), readCapacity, mutationCapacity));
    }

    [Fact]
    public async Task AuthorisedClient_GetStatus_RoundTripsOverPipe()
    {
        var pipeName = UniquePipeName();
        var server = new NamedPipeFirewallServer(
            Handler(), pipeName, authorise: null, securityFactory: CurrentUserSecurity,
            capabilityAuthorise: _ => FirewallCallerCapability.ReadStatus);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        var serverTask = server.ServeOnceAsync(cts.Token);
        var client = TrustedTestClient(pipeName);
        var response = await client.SendAsync(
            new FirewallCommandRequest(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus),
            TimeSpan.FromSeconds(15),
            cts.Token);
        await serverTask;

        Assert.True(response.Success);
        Assert.Equal(OutboundFirewallMode.AuditOnly, response.Status!.Mode);
    }

    private async Task<FirewallCommandResponse> GetStatusAsync(string pipeName, CancellationToken cancellationToken) =>
        await TrustedTestClient(pipeName).SendAsync(
            new FirewallCommandRequest(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus),
            TimeSpan.FromSeconds(10),
            cancellationToken);

    [Fact]
    public async Task AcceptLoop_KeepsServing_AfterAPeerConnectsAndVanishesWithoutSendingAnything()
    {
        // The service hands off connected predecessors to successor pipe instances. A peer
        // that connects and drops - a crash, a cancelled dashboard, a hostile local user -
        // must cost one connection, not the control channel. Losing the channel while the
        // SCM still reports Running is exactly the state that looks healthy and serves
        // nobody.
        var pipeName = UniquePipeName();
        var server = new NamedPipeFirewallServer(
            Handler(), pipeName, authorise: null, securityFactory: CurrentUserSecurity,
            capabilityAuthorise: _ => FirewallCallerCapability.ReadStatus);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));

        var loop = server.RunAsync(cts.Token);
        await server.Ready.WaitAsync(TimeSpan.FromSeconds(10), cts.Token);

        // One peer is enough to prove the expected-disconnect path. Do not manufacture a
        // capacity test here: admission reservation is covered separately below.
        for (var i = 0; i < 1; i++)
        {
            using var rude = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut);
            await rude.ConnectAsync(5000, cts.Token);
        }

        Assert.True((await GetStatusAsync(pipeName, cts.Token)).Success);
        Assert.False(loop.IsCompleted, "the accept loop must still be running");

        // Cancellation is an ordinary stop: the loop returns rather than throwing.
        await cts.CancelAsync();
        await loop.WaitAsync(TimeSpan.FromSeconds(15), CancellationToken.None);
    }

    [Fact]
    public async Task AcceptLoop_ConcurrentSilentAndAbruptPeerStormKeepsServing()
    {
        var pipeName = UniquePipeName();
        var server = new NamedPipeFirewallServer(
            Handler(), pipeName, authorise: null, securityFactory: CurrentUserSecurity,
            capabilityAuthorise: _ => FirewallCallerCapability.ReadStatus,
            requestReadTimeout: TimeSpan.FromMilliseconds(400),
            responseWriteTimeout: TimeSpan.FromSeconds(2));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var loop = server.RunAsync(cts.Token);
        await server.Ready.WaitAsync(TimeSpan.FromSeconds(10), cts.Token);

        var silentPeers = new List<NamedPipeClientStream>();
        try
        {
            for (var index = 0; index < 6; index++)
            {
                var peer = new NamedPipeClientStream(
                    ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                await peer.ConnectAsync(TimeSpan.FromSeconds(5), cts.Token);
                silentPeers.Add(peer);
            }

            var successfulAbruptConnections = 0;
            var abruptWorkers = Enumerable.Range(0, 8).Select(async _ =>
            {
                for (var index = 0; index < 25; index++)
                {
                    await using var peer = new NamedPipeClientStream(
                        ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                    try
                    {
                        await peer.ConnectAsync(TimeSpan.FromSeconds(2), cts.Token);
                        Interlocked.Increment(ref successfulAbruptConnections);
                    }
                    catch (Exception ex) when (ex is IOException or TimeoutException)
                    {
                        // Capacity rejection and scheduling timeouts are allowed under the
                        // storm; only listener loss after the peers drain is a failure.
                    }
                }
            });
            var validWorkers = Enumerable.Range(0, 6).Select(async workerIndex =>
            {
                try
                {
                    _ = await GetStatusAsync(pipeName, cts.Token);
                }
                catch (Exception ex) when (ex is IOException or TimeoutException)
                {
                    // Read admission is intentionally saturated during this phase. A
                    // busy release runner may spend the whole client budget waiting for
                    // an instance, which is equivalent to the peer-local I/O rejection
                    // for this storm. Recovery after the peers drain is asserted below.
                }
            });

            await Task.WhenAll(abruptWorkers.Concat(validWorkers));
            Assert.True(successfulAbruptConnections > 0);
            Assert.False(loop.IsCompleted, "peer-local accept I/O must not terminate the listener");
        }
        finally
        {
            foreach (var peer in silentPeers)
            {
                await peer.DisposeAsync();
            }
        }

        await Task.Delay(TimeSpan.FromSeconds(1), cts.Token);
        Assert.True((await GetStatusAsync(pipeName, cts.Token)).Success);
        Assert.False(loop.IsCompleted);

        await cts.CancelAsync();
        await loop.WaitAsync(TimeSpan.FromSeconds(15), CancellationToken.None);
    }

    [Fact]
    public async Task AcceptLoop_DefaultReservedMutationLane_SurvivesReadOnlySilentPeerSaturation()
    {
        // The denial-of-service shape that matters: a local caller opens the pipe and
        // simply holds it. With a single accept instance this locked out the dashboard
        // for the whole read timeout, and indefinitely if the peer reconnected in a loop,
        // all while the SCM reported the service as Running.
        var pipeName = UniquePipeName();
        var authority = new RecordingMutationAuthority();
        var handler = new FirewallConnectionHandler(new FirewallRequestDispatcher(
            new FirewallPolicyStore(Path.Combine(_directory, "reserved-lane-policies.json")), authority));
        var readLaneSaturated = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var rejectedReadAuthorised = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var authorisationCalls = 0;
        var server = new NamedPipeFirewallServer(
            handler, pipeName,
            authorise: null,
            securityFactory: CurrentUserSecurity,
            capabilityAuthorise: _ => Interlocked.Increment(ref authorisationCalls) switch
            {
                <= 3 => FirewallCallerCapability.ReadStatus,
                4 => SignalReadStatus(readLaneSaturated),
                5 => FirewallCallerCapability.MutateMachinePolicy,
                _ => SignalReadStatus(rejectedReadAuthorised),
            },
            requestReadTimeout: TimeSpan.FromSeconds(10),
            responseWriteTimeout: TimeSpan.FromSeconds(5));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));

        var loop = server.RunAsync(cts.Token);
        await server.Ready.WaitAsync(TimeSpan.FromSeconds(10), cts.Token);

        var silentReadPeers = new List<NamedPipeClientStream>();
        try
        {
            for (var index = 0; index < 4; index++)
            {
                var silentReadPeer = new NamedPipeClientStream(
                    ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                await silentReadPeer.ConnectAsync(TimeSpan.FromSeconds(5), cts.Token);
                silentReadPeers.Add(silentReadPeer);
            }
            await readLaneSaturated.Task.WaitAsync(TimeSpan.FromSeconds(5), cts.Token);

            // The four default standard-user permits are occupied by silent peers. The
            // mutation request must use its reserved lane rather than wait for their
            // ten-second request deadline.
            var elapsed = Stopwatch.StartNew();
            var mutationResponse = await TrustedTestClient(pipeName).SendAsync(
                new FirewallCommandRequest(
                    FirewallProtocolCodec.CurrentVersion,
                    Guid.NewGuid(),
                    FirewallCommand.EmergencyDisable),
                TimeSpan.FromSeconds(5), cts.Token);
            elapsed.Stop();

            Assert.True(mutationResponse.Success);
            Assert.Equal(1, authority.EmergencyDisableCalls);
            Assert.True(elapsed.Elapsed < TimeSpan.FromSeconds(5),
                $"reserved mutation admission took {elapsed.Elapsed} while the read deadline is 10 seconds");

            // Admission rejection closes the authenticated pipe promptly. The transport
            // intentionally reports zero-byte EOF here; the gateway tests separately hold
            // the v3-only invariant that no lower protocol is probed or cached.
            var rejected = TrustedTestClient(pipeName).SendAsync(
                new FirewallCommandRequest(
                    FirewallProtocolCodec.CurrentVersion,
                    Guid.NewGuid(),
                    FirewallCommand.GetStatus),
                TimeSpan.FromSeconds(5), cts.Token);
            await rejectedReadAuthorised.Task.WaitAsync(TimeSpan.FromSeconds(5), cts.Token);
            var rejectionElapsed = Stopwatch.StartNew();
            await Assert.ThrowsAnyAsync<IOException>(() => rejected);
            rejectionElapsed.Stop();
            Assert.True(rejectionElapsed.Elapsed < TimeSpan.FromSeconds(2),
                $"admission rejection was not prompt: {rejectionElapsed.Elapsed}");
        }
        finally
        {
            await cts.CancelAsync();
            foreach (var peer in silentReadPeers)
            {
                await peer.DisposeAsync();
            }
        }

        await loop.WaitAsync(TimeSpan.FromSeconds(15), CancellationToken.None);
    }

    [Fact]
    public async Task AcceptLoop_KeepsServing_AfterAPeerSendsGarbage()
    {
        // Same contract for an unparseable frame: the handler already refuses to answer
        // it, and the loop must go back to accepting rather than ending.
        var pipeName = UniquePipeName();
        var server = new NamedPipeFirewallServer(
            Handler(), pipeName, authorise: _ => true, securityFactory: CurrentUserSecurity);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));

        var loop = server.RunAsync(cts.Token);
        await server.Ready.WaitAsync(TimeSpan.FromSeconds(10), cts.Token);

        using (var rude = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut))
        {
            await rude.ConnectAsync(5000, cts.Token);
            await rude.WriteAsync(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }, cts.Token);
            await rude.FlushAsync(cts.Token);
        }

        Assert.True((await GetStatusAsync(pipeName, cts.Token)).Success);
        Assert.False(loop.IsCompleted, "the accept loop must still be running");

        // Cancellation is an ordinary stop: the loop returns rather than throwing.
        await cts.CancelAsync();
        await loop.WaitAsync(TimeSpan.FromSeconds(15), CancellationToken.None);
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
        var client = TrustedTestClient(pipeName);
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
        var client = TrustedTestClient(pipeName);
        var response = await client.SendAsync(
            new FirewallCommandRequest(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus),
            TimeSpan.FromSeconds(15),
            cts.Token);
        await serverTask;

        Assert.False(response.Success);
        Assert.Equal(FirewallProtocolError.Unauthorized, response.Error);
    }

    [Fact]
    public async Task DefaultClient_UserOwnedPipe_IsRefusedBeforeAnyRequestByteIsWritten()
    {
        var pipeName = UniquePipeName();
        await using var hostile = NamedPipeServerStreamAcl.Create(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            0,
            0,
            CurrentUserSecurity());
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        // Shares the observer with the injected-refusal test. Unlike that one this cannot gate the
        // client — the refusal comes from real pipe-ownership validation, not an injected callback —
        // so the observer has to tolerate the connection being torn down mid-wait.
        var observedBytes = ObserveBytesUntilClientCloseAsync(
            hostile,
            new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously),
            cts.Token);
        var client = new FirewallServiceClient(pipeName);

        var error = await Assert.ThrowsAsync<FirewallPeerValidationException>(() => client.SendAsync(
            new FirewallCommandRequest(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus),
            TimeSpan.FromSeconds(5),
            cts.Token));

        Assert.Equal(FirewallPeerValidationException.FixedMessage, error.Message);
        Assert.Equal(0, await observedBytes);
    }

    [Fact]
    public async Task InjectedPeerRefusal_IsFailClosedBeforeAnyRequestByteIsWritten()
    {
        var pipeName = UniquePipeName();
        await using var peer = NamedPipeServerStreamAcl.Create(
            pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, 0, 0, CurrentUserSecurity());
        // Generous budgets so CPU starvation under the parallel suite cannot turn a validation
        // refusal into a connect TimeoutException — that would fail a correct assertion for a
        // scheduling reason, not a behavioural one. Start the server-side read before allowing
        // the validator to throw: ConnectAsync may otherwise return and dispose the client before
        // the server's WaitForConnectionAsync continuation observes the short-lived connection.
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var peerReadStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var observedBytes = ObserveBytesUntilClientCloseAsync(peer, peerReadStarted, cts.Token);
        var client = new FirewallServiceClient(pipeName, _ =>
        {
            peerReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(30), cts.Token).GetAwaiter().GetResult();
            throw new FirewallPeerValidationException();
        });

        await Assert.ThrowsAsync<FirewallPeerValidationException>(() => client.SendAsync(
            new FirewallCommandRequest(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus),
            TimeSpan.FromSeconds(30),
            cts.Token));

        Assert.Equal(0, await observedBytes);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Client_RejectsResponseNotBoundToExactRequest(bool wrongRequestId)
    {
        var pipeName = UniquePipeName();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var serverTask = ServeRawResponseAsync(pipeName, request => new FirewallCommandResponse(
            wrongRequestId ? request.ProtocolVersion : FirewallProtocolCodec.LegacyVersion,
            wrongRequestId ? Guid.NewGuid() : request.RequestId,
            Success: true), cts.Token);
        var client = TrustedTestClient(pipeName);

        await Assert.ThrowsAsync<FirewallPeerValidationException>(() => client.SendAsync(
            new FirewallCommandRequest(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus),
            TimeSpan.FromSeconds(5), cts.Token));
        await serverTask;
    }

    [Fact]
    public async Task RealClient_ZeroByteResponseEof_IsTypedLegacyClose()
    {
        var pipeName = UniquePipeName();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var serverTask = ServeRawBytesAndCloseAsync(pipeName, [], cts.Token);
        var client = TrustedTestClient(pipeName);

        await Assert.ThrowsAsync<FirewallLegacyPeerClosedException>(() => client.SendAsync(
            new FirewallCommandRequest(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus),
            TimeSpan.FromSeconds(5), cts.Token));
        await serverTask;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RealClient_PartialResponseFrame_IsMalformedNotLegacy(bool partialPayload)
    {
        var pipeName = UniquePipeName();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var bytes = partialPayload
            ? BitConverter.GetBytes(10).Concat([(byte)'{', (byte)'"']).ToArray()
            : new byte[] { 0x01 };
        var serverTask = ServeRawBytesAndCloseAsync(pipeName, bytes, cts.Token);
        var client = TrustedTestClient(pipeName);

        var exception = await Assert.ThrowsAsync<FirewallProtocolException>(() => client.SendAsync(
            new FirewallCommandRequest(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus),
            TimeSpan.FromSeconds(5), cts.Token));
        await serverTask;

        Assert.Equal(FirewallProtocolError.InvalidRequest, exception.Error);
        Assert.Contains(partialPayload ? "payload" : "header", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TrustedSilentPeer_ReadDeadlineIsFixedTimeout()
    {
        var pipeName = UniquePipeName();
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var requestRead = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = Task.Run(async () =>
        {
            await using var server = NamedPipeServerStreamAcl.Create(
                pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous, 0, 0, CurrentUserSecurity());
            await server.WaitForConnectionAsync(serverCancellation.Token);
            _ = await FirewallProtocolCodec.ReadRequestAsync(server, serverCancellation.Token);
            requestRead.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, serverCancellation.Token);
        }, serverCancellation.Token);
        var client = TrustedTestClient(pipeName);

        // The send is started but not awaited, and the read is confirmed while it is still in
        // flight — the same shape as the sibling test below, and for a reason this one learned the
        // hard way. Awaiting a 150 ms deadline first let the client give up and tear down the pipe
        // before a loaded runner had scheduled the server's read at all: the read then failed, the
        // signal below never arrived, and the test failed on the wait rather than on anything it was
        // asserting. It blocked a release exactly once, which is how flaky tests teach people to
        // re-run until green.
        //
        // A second's budget for a scheduler to run a task and read a few hundred bytes is a wide
        // margin; the deadline still has to fire for the assertion to hold, so the test proves what
        // its name claims.
        var send = client.SendAsync(
            new FirewallCommandRequest(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus),
            TimeSpan.FromSeconds(1));
        await requestRead.Task.WaitAsync(TimeSpan.FromSeconds(10));

        var error = await Assert.ThrowsAsync<TimeoutException>(() => send);

        Assert.Equal("The WinSight firewall service did not respond.", error.Message);
        await serverCancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => serverTask);
    }

    [Fact]
    public async Task TrustedSilentPeer_CallerCancellationPropagatesWithoutTimeoutTranslation()
    {
        var pipeName = UniquePipeName();
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var requestRead = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = Task.Run(async () =>
        {
            await using var server = NamedPipeServerStreamAcl.Create(
                pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous, 0, 0, CurrentUserSecurity());
            await server.WaitForConnectionAsync(serverCancellation.Token);
            _ = await FirewallProtocolCodec.ReadRequestAsync(server, serverCancellation.Token);
            requestRead.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, serverCancellation.Token);
        }, serverCancellation.Token);
        var client = TrustedTestClient(pipeName);
        using var callerCancellation = new CancellationTokenSource();
        var send = client.SendAsync(
            new FirewallCommandRequest(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus),
            TimeSpan.FromSeconds(5), callerCancellation.Token);
        await requestRead.Task.WaitAsync(TimeSpan.FromSeconds(5));

        await callerCancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => send);

        await serverCancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => serverTask);
    }

    [Fact]
    public async Task TrustedPeerThatNeverReads_WriteDeadlineIsFixedTimeout()
    {
        var pipeName = UniquePipeName();
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var connected = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = Task.Run(async () =>
        {
            await using var server = NamedPipeServerStreamAcl.Create(
                pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous, 1, 1, CurrentUserSecurity());
            await server.WaitForConnectionAsync(serverCancellation.Token);
            connected.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, serverCancellation.Token);
        }, serverCancellation.Token);
        var client = TrustedTestClient(pipeName);
        var largePath = "C:\\" + new string('a', 12_000) + ".exe";

        var error = await Assert.ThrowsAsync<TimeoutException>(() => client.SendAsync(
            new FirewallCommandRequest(
                FirewallProtocolCodec.CurrentVersion,
                Guid.NewGuid(),
                FirewallCommand.UpsertPolicy,
                Policy: new AppFirewallPolicy(largePath, OutboundAction.Block)),
            TimeSpan.FromMilliseconds(150)));

        Assert.Equal("The WinSight firewall service did not respond.", error.Message);
        await connected.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await serverCancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => serverTask);
    }

    [Fact]
    public async Task InitialFirstInstanceCollision_FailsInsteadOfJoiningAttackerOwnedName()
    {
        var pipeName = UniquePipeName();
        await using var squatter = NamedPipeServerStreamAcl.Create(
            pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, 0, 0, CurrentUserSecurity());
        var server = new NamedPipeFirewallServer(
            Handler(), pipeName, authorise: _ => true, securityFactory: CurrentUserSecurity);

        var error = await Record.ExceptionAsync(() => server.RunAsync(CancellationToken.None));

        Assert.NotNull(error);
        Assert.True(error is IOException or UnauthorizedAccessException, error.GetType().FullName);
        Assert.False(server.Ready.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task InitialSecurityCreationFailure_FaultsReadyAndRunAsync()
    {
        var server = new NamedPipeFirewallServer(
            Handler(), UniquePipeName(), authorise: _ => true,
            securityFactory: () => throw new InvalidOperationException("test initial creation failure"));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            server.RunAsync(CancellationToken.None));

        Assert.Equal("test initial creation failure", error.Message);
        await Assert.ThrowsAsync<InvalidOperationException>(() => server.Ready);
    }

    [Fact]
    public async Task SuccessorCreationFailure_IsTerminalAfterReadiness_AndReleasesThePipeName()
    {
        var pipeName = UniquePipeName();
        var securityCalls = 0;
        var server = new NamedPipeFirewallServer(
            Handler(), pipeName, authorise: _ => true,
            securityFactory: () => Interlocked.Increment(ref securityCalls) == 1
                ? CurrentUserSecurity()
                : throw new InvalidOperationException("test successor creation failure"));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        var runTask = server.RunAsync(cts.Token);
        await server.Ready.WaitAsync(TimeSpan.FromSeconds(5), cts.Token);
        await using (var client = new NamedPipeClientStream(
            ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
        {
            await client.ConnectAsync(TimeSpan.FromSeconds(5), cts.Token);
        }

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => runTask);
        Assert.Equal("test successor creation failure", error.Message);
        Assert.True(server.Ready.IsCompletedSuccessfully);

        await using var replacement = NamedPipeServerStreamAcl.Create(
            pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 0, 0, CurrentUserSecurity());
    }

    [Fact]
    public async Task UnexpectedAuthorisationFailure_IsTerminal()
    {
        var pipeName = UniquePipeName();
        var server = new NamedPipeFirewallServer(
            Handler(), pipeName,
            authorise: _ => throw new NotSupportedException("test authorisation failure"),
            securityFactory: CurrentUserSecurity);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        var runTask = server.RunAsync(cts.Token);
        await server.Ready.WaitAsync(TimeSpan.FromSeconds(5), cts.Token);
        await using (var client = new NamedPipeClientStream(
            ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
        {
            await client.ConnectAsync(TimeSpan.FromSeconds(5), cts.Token);
        }

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => runTask);
        Assert.IsType<NotSupportedException>(error.InnerException);
    }

    [Fact]
    public async Task UnexpectedDispatcherFailure_IsTerminal()
    {
        var pipeName = UniquePipeName();
        var handler = new FirewallConnectionHandler(new FirewallRequestDispatcher(
            new FirewallPolicyStore(Path.Combine(_directory, "dispatcher-failure-policies.json")),
            new ThrowingStatusAuthority()));
        var server = new NamedPipeFirewallServer(
            handler, pipeName, authorise: null, securityFactory: CurrentUserSecurity,
            capabilityAuthorise: _ => FirewallCallerCapability.ReadStatus);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        var runTask = server.RunAsync(cts.Token);
        await server.Ready.WaitAsync(TimeSpan.FromSeconds(5), cts.Token);
        await using (var client = new NamedPipeClientStream(
            ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
        {
            await client.ConnectAsync(TimeSpan.FromSeconds(5), cts.Token);
            await FirewallProtocolCodec.WriteRequestAsync(client, new FirewallCommandRequest(
                FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus), cts.Token);
            await client.FlushAsync(cts.Token);
        }

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => runTask);
        Assert.IsType<NotSupportedException>(error.InnerException);
    }

    [Fact]
    public async Task FatalConnection_DrainsNonCooperativeMutationWithinTheConfiguredBound()
    {
        var pipeName = UniquePipeName();
        var authority = new NonCooperativeEmergencyAuthority();
        var handler = new FirewallConnectionHandler(new FirewallRequestDispatcher(
            new FirewallPolicyStore(Path.Combine(_directory, "non-cooperative-policies.json")), authority));
        var authorisationCalls = 0;
        var server = new NamedPipeFirewallServer(
            handler, pipeName, authorise: null, securityFactory: CurrentUserSecurity,
            capabilityAuthorise: _ => Interlocked.Increment(ref authorisationCalls) == 1
                ? FirewallCallerCapability.MutateMachinePolicy
                : throw new NotSupportedException("test terminal authorisation failure"),
            requestReadTimeout: TimeSpan.FromSeconds(10),
            responseWriteTimeout: TimeSpan.FromSeconds(5),
            readAdmissionCapacity: 4,
            mutationAdmissionCapacity: 2,
            terminalDrainTimeout: TimeSpan.FromMilliseconds(100));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        var runTask = server.RunAsync(cts.Token);
        await server.Ready.WaitAsync(TimeSpan.FromSeconds(5), cts.Token);
        await using var blockedMutation = new NamedPipeClientStream(
            ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await blockedMutation.ConnectAsync(TimeSpan.FromSeconds(5), cts.Token);
        await FirewallProtocolCodec.WriteRequestAsync(blockedMutation, new FirewallCommandRequest(
            FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.EmergencyDisable), cts.Token);
        await blockedMutation.FlushAsync(cts.Token);
        await authority.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5), cts.Token);

        await using (var fatalPeer = new NamedPipeClientStream(
            ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
        {
            await fatalPeer.ConnectAsync(TimeSpan.FromSeconds(5), cts.Token);
        }

        var elapsed = Stopwatch.StartNew();
        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            runTask.WaitAsync(TimeSpan.FromSeconds(2), cts.Token));
        elapsed.Stop();
        Assert.IsType<NotSupportedException>(failure.InnerException);
        Assert.True(elapsed.Elapsed < TimeSpan.FromSeconds(2),
            $"terminal drain exceeded its bounded test window: {elapsed.Elapsed}");

        await using (var replacement = NamedPipeServerStreamAcl.Create(
            pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 0, 0, CurrentUserSecurity()))
        {
        }

        authority.Release();
        await authority.Completed.Task.WaitAsync(TimeSpan.FromSeconds(5), cts.Token);
    }

    [Fact]
    public async Task HealthyChurn_NeverReleasesFirstPipeInstanceOwnership()
    {
        var pipeName = UniquePipeName();
        var server = new NamedPipeFirewallServer(
            Handler(), pipeName, authorise: null, securityFactory: CurrentUserSecurity,
            capabilityAuthorise: _ => FirewallCallerCapability.ReadStatus);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var loop = server.RunAsync(cts.Token);
        await server.Ready.WaitAsync(TimeSpan.FromSeconds(5), cts.Token);

        for (var attempt = 0; attempt < 4; attempt++)
        {
            await using (var churn = new NamedPipeClientStream(
                ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
            {
                await churn.ConnectAsync(TimeSpan.FromSeconds(5), cts.Token);
            }

            AssertFirstPipeInstanceClaimFails(pipeName);
            Assert.True((await GetStatusAsync(pipeName, cts.Token)).Success);
            AssertFirstPipeInstanceClaimFails(pipeName);
            Assert.False(loop.IsCompleted);
        }

        await cts.CancelAsync();
        await loop.WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None);
        await using var replacement = NamedPipeServerStreamAcl.Create(
            pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 0, 0, CurrentUserSecurity());
    }

    [Fact]
    public async Task SuccessorHandoff_KeepsTheConnectedPredecessorOwningTheNamespaceUntilSuccessorExists()
    {
        var pipeName = UniquePipeName();
        var securityCalls = 0;
        var secondFactoryEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseSecondFactory = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new NamedPipeFirewallServer(
            Handler(), pipeName, authorise: null,
            securityFactory: () =>
            {
                if (Interlocked.Increment(ref securityCalls) == 2)
                {
                    secondFactoryEntered.TrySetResult();
                    releaseSecondFactory.Task.GetAwaiter().GetResult();
                }
                return CurrentUserSecurity();
            },
            capabilityAuthorise: _ => FirewallCallerCapability.ReadStatus,
            requestReadTimeout: TimeSpan.FromSeconds(10));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var loop = server.RunAsync(cts.Token);
        await server.Ready.WaitAsync(TimeSpan.FromSeconds(5), cts.Token);

        await using var predecessor = new NamedPipeClientStream(
            ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await predecessor.ConnectAsync(TimeSpan.FromSeconds(5), cts.Token);
        await secondFactoryEntered.Task.WaitAsync(TimeSpan.FromSeconds(5), cts.Token);

        // The second factory is deliberately stopped before a successor exists. The
        // connected predecessor must still carry FirstPipeInstance ownership here.
        AssertFirstPipeInstanceClaimFails(pipeName);
        releaseSecondFactory.TrySetResult();

        Assert.True((await GetStatusAsync(pipeName, cts.Token)).Success);
        Assert.False(loop.IsCompleted);

        await cts.CancelAsync();
        await loop.WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None);
    }

    [Fact]
    public async Task AdmissionPermits_RemainHeldUntilBlockedDisposalCompletes()
    {
        var pipeName = UniquePipeName();
        var authority = new RecordingMutationAuthority();
        var handler = new FirewallConnectionHandler(new FirewallRequestDispatcher(
            new FirewallPolicyStore(Path.Combine(_directory, "permit-dispose-policies.json")), authority));
        var authorisationCalls = 0;
        var hookEnteredCount = 0;
        var hookExitedCount = 0;
        var allInitialHooksEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var allInitialHooksExited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseHook = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new NamedPipeFirewallServer(
            handler, pipeName, authorise: null, securityFactory: CurrentUserSecurity,
            capabilityAuthorise: _ => Interlocked.Increment(ref authorisationCalls) switch
            {
                <= 4 => FirewallCallerCapability.ReadStatus,
                5 => FirewallCallerCapability.MutateMachinePolicy,
                _ => FirewallCallerCapability.ReadStatus,
            },
            requestReadTimeout: TimeSpan.FromSeconds(10),
            responseWriteTimeout: TimeSpan.FromSeconds(5),
            readAdmissionCapacity: 4,
            mutationAdmissionCapacity: 2,
            beforeAdmittedConnectionDispose: () =>
            {
                if (Interlocked.Increment(ref hookEnteredCount) == 5)
                {
                    allInitialHooksEntered.TrySetResult();
                }
                releaseHook.Task.GetAwaiter().GetResult();
                if (Interlocked.Increment(ref hookExitedCount) == 5)
                {
                    allInitialHooksExited.TrySetResult();
                }
            });
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var loop = server.RunAsync(cts.Token);
        await server.Ready.WaitAsync(TimeSpan.FromSeconds(5), cts.Token);

        try
        {
            for (var index = 0; index < 4; index++)
            {
                Assert.True((await GetStatusAsync(pipeName, cts.Token)).Success);
            }
            var mutation = await TrustedTestClient(pipeName).SendAsync(
                new FirewallCommandRequest(
                    FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.EmergencyDisable),
                TimeSpan.FromSeconds(5), cts.Token);
            Assert.True(mutation.Success);
            await allInitialHooksEntered.Task.WaitAsync(TimeSpan.FromSeconds(5), cts.Token);

            for (var churn = 0; churn < 2; churn++)
            {
                await Assert.ThrowsAnyAsync<IOException>(() =>
                    GetStatusAsync(pipeName, cts.Token));
                Assert.False(loop.IsCompleted, "rejected churn must not make successor creation terminal");
            }

            releaseHook.TrySetResult();
            await allInitialHooksExited.Task.WaitAsync(TimeSpan.FromSeconds(5), cts.Token);
            Assert.True((await GetStatusAsync(pipeName, cts.Token)).Success);
        }
        finally
        {
            releaseHook.TrySetResult();
            await cts.CancelAsync();
        }

        await loop.WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None);
    }

    [Fact]
    public async Task RunAsync_UsesOneReservedListenerForConsecutiveClients()
    {
        var pipeName = UniquePipeName();
        var server = new NamedPipeFirewallServer(
            Handler(), pipeName, authorise: _ => true, securityFactory: CurrentUserSecurity);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var runTask = server.RunAsync(cts.Token);
        await server.Ready.WaitAsync(TimeSpan.FromSeconds(5));

        for (var index = 0; index < 2; index++)
        {
            var client = TrustedTestClient(pipeName);
            var response = await client.SendAsync(
                new FirewallCommandRequest(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus),
                TimeSpan.FromSeconds(5), cts.Token);
            Assert.True(response.Success);
        }

        cts.Cancel();
        await runTask;
    }

    [Fact]
    public async Task SilentClient_DoesNotBlockSuccessorOrTheNextClient()
    {
        var pipeName = UniquePipeName();
        var server = new NamedPipeFirewallServer(
            Handler(), pipeName, authorise: _ => true, securityFactory: CurrentUserSecurity,
            requestReadTimeout: TimeSpan.FromMilliseconds(150));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var runTask = server.RunAsync(cts.Token);
        await server.Ready.WaitAsync(TimeSpan.FromSeconds(5));
        await using var silent = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await silent.ConnectAsync(TimeSpan.FromSeconds(5), cts.Token);

        // The successor is posted before this silent predecessor enters its 150 ms
        // read deadline. A real request must therefore progress immediately, not after
        // that deadline.
        var client = TrustedTestClient(pipeName);
        var response = await client.SendAsync(
            new FirewallCommandRequest(FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus),
            TimeSpan.FromSeconds(5), cts.Token);

        Assert.True(response.Success);
        cts.Cancel();
        await runTask;
    }

    [Fact]
    public async Task ResponseWriteTimeout_ReleasesAdmissionWhenClientSendsValidRequestButNeverReadsResponse()
    {
        var pipeName = UniquePipeName();
        var handlerDisposed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new NamedPipeFirewallServer(
            Handler(), pipeName, authorise: null, securityFactory: CurrentUserSecurity,
            capabilityAuthorise: _ => FirewallCallerCapability.ReadStatus,
            requestReadTimeout: TimeSpan.FromSeconds(5),
            responseWriteTimeout: TimeSpan.FromMilliseconds(150),
            readAdmissionCapacity: 4,
            mutationAdmissionCapacity: 2,
            beforeAdmittedConnectionDispose: () => handlerDisposed.TrySetResult());
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var runTask = server.RunAsync(cts.Token);
        await server.Ready.WaitAsync(TimeSpan.FromSeconds(5), cts.Token);

        await using var nonReadingClient = new NamedPipeClientStream(
            ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await nonReadingClient.ConnectAsync(TimeSpan.FromSeconds(5), cts.Token);
        await FirewallProtocolCodec.WriteRequestAsync(nonReadingClient, new FirewallCommandRequest(
            FirewallProtocolCodec.CurrentVersion, Guid.NewGuid(), FirewallCommand.GetStatus), cts.Token);
        await nonReadingClient.FlushAsync(cts.Token);

        // Whether Windows buffers this compact response or its write deadline expires,
        // the client never consumes it. The admission must nevertheless be released;
        // a handler stuck behind a non-reading peer would otherwise exhaust the listener.
        await handlerDisposed.Task.WaitAsync(TimeSpan.FromSeconds(2), cts.Token);
        Assert.False(runTask.IsCompleted);

        await cts.CancelAsync();
        await runTask.WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None);
    }

    private static FirewallCallerCapability SignalReadStatus(TaskCompletionSource signal)
    {
        signal.TrySetResult();
        return FirewallCallerCapability.ReadStatus;
    }

    private static void AssertFirstPipeInstanceClaimFails(string pipeName)
    {
        var error = Record.Exception(() =>
        {
            using var hostile = NamedPipeServerStreamAcl.Create(
                pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 0, 0, CurrentUserSecurity());
        });
        Assert.NotNull(error);
        Assert.True(error is IOException or UnauthorizedAccessException, error.GetType().FullName);
    }

    private sealed class RecordingMutationAuthority : IFirewallMutationAuthority
    {
        public int EmergencyDisableCalls { get; private set; }
        public bool EngineSupported => true;
        public Task UpsertPolicyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
        public Task RemovePolicyAsync(string executablePath, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
        public Task<OutboundFirewallConfiguration> EnableEnforcementAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(OutboundFirewallConfiguration.Empty);
        public Task<OutboundFirewallConfiguration> EmergencyDisableAsync(CancellationToken cancellationToken = default)
        {
            EmergencyDisableCalls++;
            return Task.FromResult(OutboundFirewallConfiguration.Empty);
        }
    }

    private sealed class ThrowingStatusAuthority : IFirewallMutationAuthority
    {
        public bool EngineSupported => true;
        public Task<FirewallRuntimeStatus> GetRuntimeStatusAsync(CancellationToken cancellationToken = default) =>
            throw new NotSupportedException("test dispatcher failure");
        public Task UpsertPolicyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
        public Task RemovePolicyAsync(string executablePath, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
        public Task<OutboundFirewallConfiguration> EnableEnforcementAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(OutboundFirewallConfiguration.Empty);
        public Task<OutboundFirewallConfiguration> EmergencyDisableAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(OutboundFirewallConfiguration.Empty);
    }

    private sealed class NonCooperativeEmergencyAuthority : IFirewallMutationAuthority
    {
        private readonly TaskCompletionSource<OutboundFirewallConfiguration> _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Completed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool EngineSupported => true;
        public Task UpsertPolicyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
        public Task RemovePolicyAsync(string executablePath, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
        public Task<OutboundFirewallConfiguration> EnableEnforcementAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(OutboundFirewallConfiguration.Empty);

        public async Task<OutboundFirewallConfiguration> EmergencyDisableAsync(CancellationToken cancellationToken = default)
        {
            Entered.TrySetResult();
            try
            {
                return await _release.Task.ConfigureAwait(false);
            }
            finally
            {
                Completed.TrySetResult();
            }
        }

        public void Release() => _release.TrySetResult(OutboundFirewallConfiguration.Empty);
    }

    [Fact]
    public async Task ResponseWriteTimeout_DoesNotCancelOrDuplicateCompletedDispatch()
    {
        var store = new FirewallPolicyStore(Path.Combine(_directory, "write-timeout-policies.json"));
        var authority = new RecordingTimeoutAuthority();
        var handler = new FirewallConnectionHandler(new FirewallRequestDispatcher(store, authority));
        var request = new FirewallCommandRequest(
            FirewallProtocolCodec.CurrentVersion,
            Guid.NewGuid(),
            FirewallCommand.UpsertPolicy,
            Policy: new AppFirewallPolicy(@"C:\apps\one.exe", OutboundAction.Block));
        await using var encoded = new MemoryStream();
        await FirewallProtocolCodec.WriteRequestAsync(encoded, request);
        await using var stream = new BlockingWriteDuplexStream(encoded.ToArray());

        await handler.HandleAsync(
            stream,
            FirewallCallerCapability.MutateMachinePolicy,
            TimeSpan.FromSeconds(1),
            TimeSpan.FromMilliseconds(50));

        Assert.Equal(1, authority.UpsertCalls);
        Assert.False(authority.DispatchTokenWasCancelled);
        Assert.Equal(1, stream.WriteAttempts);
    }

    private static async Task ServeRawResponseAsync(
        string pipeName,
        Func<FirewallCommandRequest, FirewallCommandResponse> responseFactory,
        CancellationToken cancellationToken)
    {
        await using var server = NamedPipeServerStreamAcl.Create(
            pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, 0, 0, CurrentUserSecurity());
        await server.WaitForConnectionAsync(cancellationToken);
        var request = await FirewallProtocolCodec.ReadRequestAsync(server, cancellationToken);
        await FirewallProtocolCodec.WriteResponseAsync(server, responseFactory(request), cancellationToken);
    }

    private static async Task<int> ObserveBytesUntilClientCloseAsync(
        NamedPipeServerStream peer,
        TaskCompletionSource readStarted,
        CancellationToken cancellationToken)
    {
        try
        {
            await peer.WaitForConnectionAsync(cancellationToken);
            var buffer = new byte[1];
            var read = peer.ReadAsync(buffer, cancellationToken);
            readStarted.TrySetResult();
            return await read;
        }
        catch (IOException)
        {
            // A client that refuses its peer disposes the pipe at once, and whether that surfaces
            // here as a clean end-of-stream or tears down a still-pending WaitForConnection is a
            // scheduling detail. CI hits the second often enough to fail a correct refusal.
            // Both mean the same thing for this assertion: no request byte reached this server. A
            // byte that was written and delivered would have been returned by ReadAsync before any
            // teardown could be observed, so mapping the tear-down to zero cannot hide a write.
            readStarted.TrySetResult();
            return 0;
        }
    }

    private static async Task ServeRawBytesAndCloseAsync(
        string pipeName,
        byte[] bytes,
        CancellationToken cancellationToken)
    {
        await using var server = NamedPipeServerStreamAcl.Create(
            pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, 0, 0, CurrentUserSecurity());
        await server.WaitForConnectionAsync(cancellationToken);
        _ = await FirewallProtocolCodec.ReadRequestAsync(server, cancellationToken);
        if (bytes.Length > 0)
        {
            await server.WriteAsync(bytes, cancellationToken);
            await server.FlushAsync(cancellationToken);
        }
    }

    private sealed class RecordingTimeoutAuthority : IFirewallMutationAuthority
    {
        public int UpsertCalls { get; private set; }
        public bool DispatchTokenWasCancelled { get; private set; }
        public bool EngineSupported => true;
        public Task UpsertPolicyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        {
            UpsertCalls++;
            DispatchTokenWasCancelled = cancellationToken.IsCancellationRequested;
            return Task.CompletedTask;
        }
        public Task RemovePolicyAsync(string executablePath, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
        public Task<OutboundFirewallConfiguration> EnableEnforcementAsync(CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
        public Task<OutboundFirewallConfiguration> EmergencyDisableAsync(CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class BlockingWriteDuplexStream(byte[] request) : Stream
    {
        private readonly MemoryStream _request = new(request, writable: false);
        public int WriteAttempts { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override int Read(byte[] buffer, int offset, int count) => _request.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            _request.ReadAsync(buffer, cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            WriteAttempts++;
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}
