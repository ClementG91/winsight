using WinSight.Firewall;
using Xunit;

namespace WinSight.Application.Tests;

public sealed class FirewallServiceGatewayTests
{
    [Fact]
    public async Task GetViewAsync_ServiceUnreachable_DegradesToUnavailableAuditOnly()
    {
        var gateway = new FirewallServiceGateway(new ThrowingClient());

        var view = await gateway.GetViewAsync();

        Assert.False(view.ServiceAvailable);
        Assert.Equal(OutboundFirewallMode.AuditOnly, view.Mode);
        Assert.False(view.EnforcementEnabled);
        Assert.Empty(view.Policies);
    }

    [Fact]
    public async Task GetViewAsync_ServiceAvailable_ReturnsStatusAndPolicies()
    {
        var gateway = new FirewallServiceGateway(new ScriptedClient(
            status: new FirewallServiceStatus(OutboundFirewallMode.AuditOnly, EngineSupported: false, EnforcementEnabled: false),
            pages:
            [
                (new[]
                {
                    new AppFirewallPolicy(@"C:\apps\a.exe", OutboundAction.Block),
                    new AppFirewallPolicy(@"C:\apps\b.exe", OutboundAction.Allow),
                }, null),
            ]));

        var view = await gateway.GetViewAsync();

        Assert.True(view.ServiceAvailable);
        Assert.Equal(OutboundFirewallMode.AuditOnly, view.Mode);
        Assert.Equal(2, view.Policies.Count);
    }

    [Fact]
    public async Task GetViewAsync_PersistedEnforcementWithFailedRuntime_ProjectsDegradedNotActive()
    {
        var gateway = new FirewallServiceGateway(new ScriptedClient(
            status: new FirewallServiceStatus(
                OutboundFirewallMode.Enforcement,
                EngineSupported: true,
                EnforcementEnabled: false,
                EffectiveState: FirewallEnforcementState.Degraded),
            pages: [(Array.Empty<AppFirewallPolicy>(), null)]));

        var view = await gateway.GetViewAsync();

        Assert.True(view.ServiceAvailable);
        Assert.Equal(OutboundFirewallMode.Enforcement, view.Mode);
        Assert.False(view.EnforcementEnabled);
        Assert.Equal(FirewallEnforcementState.Degraded, view.EffectiveState);
    }

    [Theory]
    [InlineData(FirewallEnforcementState.AuditOnly, OutboundFirewallMode.AuditOnly)]
    [InlineData(FirewallEnforcementState.Degraded, OutboundFirewallMode.Enforcement)]
    public async Task GetViewAsync_FinalStatusAfterPagesNeverKeepsStaleActive(
        FirewallEnforcementState finalState,
        OutboundFirewallMode finalMode)
    {
        var client = new StatusChangesDuringPagesClient(finalState, finalMode);
        var gateway = new FirewallServiceGateway(client);

        var view = await gateway.GetViewAsync();

        Assert.True(view.ServiceAvailable);
        Assert.Equal(finalMode, view.Mode);
        Assert.Equal(finalState, view.EffectiveState);
        Assert.False(view.EnforcementEnabled);
        Assert.True(client.PageWasRead);
        Assert.True(client.StatusCalls >= 3);
    }

    // An old service closes v3 and v2 probes. Only those read-only status probes may be retried;
    // the v1 response has no runtime proof and must never project Active.
    [Fact]
    public async Task GetViewAsync_OlderService_FallsBackWithReadOnlyProbeAndNeverClaimsActive()
    {
        var client = new LegacyOnlyClient();
        var gateway = new FirewallServiceGateway(client);

        var view = await gateway.GetViewAsync();

        Assert.True(view.ServiceAvailable);
        Assert.Collection(client.Requests.Take(3),
            request =>
            {
                Assert.Equal(FirewallProtocolCodec.CurrentVersion, request.ProtocolVersion);
                Assert.Equal(FirewallCommand.GetStatus, request.Command);
            },
            request =>
            {
                Assert.Equal(FirewallProtocolCodec.RuntimeProofVersion, request.ProtocolVersion);
                Assert.Equal(FirewallCommand.GetStatus, request.Command);
            },
            request =>
            {
                Assert.Equal(FirewallProtocolCodec.LegacyVersion, request.ProtocolVersion);
                Assert.Equal(FirewallCommand.GetStatus, request.Command);
            });
        Assert.DoesNotContain(client.Requests, request => request.Command is
            FirewallCommand.UpsertPolicy or FirewallCommand.RemovePolicy or
            FirewallCommand.EmergencyDisable or FirewallCommand.EnableEnforcement);
        Assert.False(view.EnforcementEnabled);
        Assert.Equal(FirewallEnforcementState.Degraded, view.EffectiveState);
    }

    // Negotiation happens before mutation. If v2 is rejected, only GetStatus may be repeated as
    // v1; EnableEnforcement must appear exactly once and only after the cached v1 capability.
    [Fact]
    public async Task EnableEnforcementAsync_OlderService_NeverReplaysMutationDuringFallback()
    {
        var client = new LegacyOnlyClient();
        var gateway = new FirewallServiceGateway(client);

        var result = await gateway.EnableEnforcementAsync();

        Assert.Equal(FirewallMutationResult.Applied, result);
        Assert.Collection(client.Requests,
            request =>
            {
                Assert.Equal(FirewallProtocolCodec.CurrentVersion, request.ProtocolVersion);
                Assert.Equal(FirewallCommand.GetStatus, request.Command);
            },
            request =>
            {
                Assert.Equal(FirewallProtocolCodec.RuntimeProofVersion, request.ProtocolVersion);
                Assert.Equal(FirewallCommand.GetStatus, request.Command);
            },
            request =>
            {
                Assert.Equal(FirewallProtocolCodec.LegacyVersion, request.ProtocolVersion);
                Assert.Equal(FirewallCommand.GetStatus, request.Command);
            },
            request =>
            {
                Assert.Equal(FirewallProtocolCodec.LegacyVersion, request.ProtocolVersion);
                Assert.Equal(FirewallCommand.EnableEnforcement, request.Command);
            });
        Assert.Equal(1, client.Requests.Count(request => request.Command == FirewallCommand.EnableEnforcement));
    }

    [Fact]
    public async Task GetViewAsync_PeerValidationFailure_NeverFallsBackOrCachesAProtocol()
    {
        var client = new AlwaysPeerRejectingClient();
        var gateway = new FirewallServiceGateway(client);

        Assert.False((await gateway.GetViewAsync()).ServiceAvailable);
        Assert.False((await gateway.GetViewAsync()).ServiceAvailable);

        Assert.Equal(2, client.Requests.Count);
        Assert.All(client.Requests, request =>
        {
            Assert.Equal(FirewallProtocolCodec.CurrentVersion, request.ProtocolVersion);
            Assert.Equal(FirewallCommand.GetStatus, request.Command);
        });
    }

    [Fact]
    public async Task Mutation_PeerValidationFailureDuringNegotiation_SendsNoMutationAndNoLegacyProbe()
    {
        var client = new AlwaysPeerRejectingClient();
        var gateway = new FirewallServiceGateway(client);

        var result = await gateway.EnableEnforcementAsync();

        Assert.Equal(FirewallMutationResult.ServiceUnavailable, result);
        var probe = Assert.Single(client.Requests);
        Assert.Equal(FirewallProtocolCodec.CurrentVersion, probe.ProtocolVersion);
        Assert.Equal(FirewallCommand.GetStatus, probe.Command);
    }

    [Fact]
    public async Task Mutation_PeerValidationFailureAfterV2Probe_IsNeverRetriedOrDowngraded()
    {
        var client = new ProbeThenMutationPeerRejectingClient();
        var gateway = new FirewallServiceGateway(client);

        var result = await gateway.EmergencyDisableAsync();

        Assert.Equal(FirewallMutationResult.ServiceUnavailable, result);
        Assert.Collection(client.Requests,
            request =>
            {
                Assert.Equal(FirewallProtocolCodec.CurrentVersion, request.ProtocolVersion);
                Assert.Equal(FirewallCommand.GetStatus, request.Command);
            },
            request =>
            {
                Assert.Equal(FirewallProtocolCodec.CurrentVersion, request.ProtocolVersion);
                Assert.Equal(FirewallCommand.EmergencyDisable, request.Command);
            });
        Assert.Equal(1, client.Requests.Count(request => request.Command == FirewallCommand.EmergencyDisable));
    }

    [Fact]
    public async Task GetViewAsync_PagesThroughAllPolicies()
    {
        var gateway = new FirewallServiceGateway(new ScriptedClient(
            status: new FirewallServiceStatus(OutboundFirewallMode.AuditOnly, EngineSupported: false, EnforcementEnabled: false),
            pages:
            [
                (new[] { new AppFirewallPolicy(@"C:\apps\a.exe", OutboundAction.Ask) }, 1),
                (new[] { new AppFirewallPolicy(@"C:\apps\b.exe", OutboundAction.Ask) }, 2),
                (new[] { new AppFirewallPolicy(@"C:\apps\c.exe", OutboundAction.Ask) }, null),
            ]));

        var view = await gateway.GetViewAsync();

        Assert.True(view.ServiceAvailable);
        Assert.Equal(3, view.Policies.Count);
    }

    [Fact]
    public async Task GetViewAsync_V3ContinuationsEchoTheFirstSnapshotToken()
    {
        var client = new ScriptedClient(
            status: new FirewallServiceStatus(
                OutboundFirewallMode.AuditOnly, EngineSupported: true, EnforcementEnabled: false),
            pages:
            [
                ([new AppFirewallPolicy(@"C:\apps\a.exe", OutboundAction.Ask)], 1),
                ([new AppFirewallPolicy(@"C:\apps\b.exe", OutboundAction.Ask)], null),
            ],
            pendingPages:
            [
                ([new PendingOutboundApp(@"C:\apps\p1.exe", "1.2.3.4:443",
                    DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, 1)], 1),
                ([new PendingOutboundApp(@"C:\apps\p2.exe", "1.2.3.4:443",
                    DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, 1)], null),
            ]);
        var gateway = new FirewallServiceGateway(client);

        var view = await gateway.GetViewAsync();

        Assert.True(view.ServiceAvailable);
        var policyPages = client.Requests.Where(request => request.Command == FirewallCommand.ListPolicies).ToArray();
        var pendingPages = client.Requests.Where(request => request.Command == FirewallCommand.ListPending).ToArray();
        Assert.Null(policyPages[0].SnapshotVersion);
        Assert.Equal(new string('A', 64), policyPages[1].SnapshotVersion);
        Assert.Null(pendingPages[0].SnapshotVersion);
        Assert.Equal(new string('B', 64), pendingPages[1].SnapshotVersion);
    }

    [Fact]
    public async Task GetViewAsync_PagesThroughAllPendingApplications()
    {
        var seen = DateTimeOffset.UtcNow;
        var gateway = new FirewallServiceGateway(new ScriptedClient(
            status: new FirewallServiceStatus(OutboundFirewallMode.AuditOnly, EngineSupported: false, EnforcementEnabled: false),
            pages: [(Array.Empty<AppFirewallPolicy>(), null)],
            pendingPages:
            [
                ([new PendingOutboundApp(@"C:\apps\a.exe", "1.2.3.4:443", seen, seen, 1)], 1),
                ([new PendingOutboundApp(@"C:\apps\b.exe", "1.2.3.4:443", seen, seen, 1)], null),
            ]));

        var view = await gateway.GetViewAsync();

        Assert.True(view.ServiceAvailable);
        Assert.Equal(2, view.Pending.Count);
    }

    [Theory]
    [InlineData(FirewallCommand.ListPolicies, PaginationFault.FirstPageFailure)]
    [InlineData(FirewallCommand.ListPolicies, PaginationFault.FirstPageNull)]
    [InlineData(FirewallCommand.ListPolicies, PaginationFault.IntermediateFailure)]
    [InlineData(FirewallCommand.ListPolicies, PaginationFault.IntermediateNull)]
    [InlineData(FirewallCommand.ListPolicies, PaginationFault.NonAdvancing)]
    [InlineData(FirewallCommand.ListPolicies, PaginationFault.WrongNextOffset)]
    [InlineData(FirewallCommand.ListPolicies, PaginationFault.EmptyWithNextOffset)]
    [InlineData(FirewallCommand.ListPolicies, PaginationFault.MaxPagesExhausted)]
    [InlineData(FirewallCommand.ListPending, PaginationFault.FirstPageFailure)]
    [InlineData(FirewallCommand.ListPending, PaginationFault.FirstPageNull)]
    [InlineData(FirewallCommand.ListPending, PaginationFault.IntermediateFailure)]
    [InlineData(FirewallCommand.ListPending, PaginationFault.IntermediateNull)]
    [InlineData(FirewallCommand.ListPending, PaginationFault.NonAdvancing)]
    [InlineData(FirewallCommand.ListPending, PaginationFault.WrongNextOffset)]
    [InlineData(FirewallCommand.ListPending, PaginationFault.EmptyWithNextOffset)]
    [InlineData(FirewallCommand.ListPending, PaginationFault.MaxPagesExhausted)]
    public async Task GetViewAsync_IncompletePaginationNeverPresentsPartialDataAsComplete(
        FirewallCommand command,
        PaginationFault fault)
    {
        var client = new PaginationFaultClient(command, fault);
        var gateway = new FirewallServiceGateway(client);

        var view = await gateway.GetViewAsync();

        Assert.False(view.ServiceAvailable);
        Assert.Empty(view.Policies);
        Assert.Empty(view.Pending);
        Assert.Contains(client.Requests, request => request.Command == command);
        Assert.DoesNotContain(client.Requests, request => request.Command is
            FirewallCommand.UpsertPolicy or FirewallCommand.RemovePolicy or
            FirewallCommand.EnableEnforcement or FirewallCommand.EmergencyDisable);
    }

    [Theory]
    [InlineData(FirewallCommand.ListPolicies, SnapshotFault.MissingToken)]
    [InlineData(FirewallCommand.ListPolicies, SnapshotFault.MissingCount)]
    [InlineData(FirewallCommand.ListPolicies, SnapshotFault.TokenChanges)]
    [InlineData(FirewallCommand.ListPolicies, SnapshotFault.CountChanges)]
    [InlineData(FirewallCommand.ListPolicies, SnapshotFault.DuplicateAcrossPages)]
    [InlineData(FirewallCommand.ListPolicies, SnapshotFault.EarlyTerminal)]
    [InlineData(FirewallCommand.ListPolicies, SnapshotFault.LateTerminal)]
    [InlineData(FirewallCommand.ListPolicies, SnapshotFault.GlobalLimitExceeded)]
    [InlineData(FirewallCommand.ListPending, SnapshotFault.MissingToken)]
    [InlineData(FirewallCommand.ListPending, SnapshotFault.MissingCount)]
    [InlineData(FirewallCommand.ListPending, SnapshotFault.TokenChanges)]
    [InlineData(FirewallCommand.ListPending, SnapshotFault.CountChanges)]
    [InlineData(FirewallCommand.ListPending, SnapshotFault.DuplicateAcrossPages)]
    [InlineData(FirewallCommand.ListPending, SnapshotFault.EarlyTerminal)]
    [InlineData(FirewallCommand.ListPending, SnapshotFault.LateTerminal)]
    [InlineData(FirewallCommand.ListPending, SnapshotFault.GlobalLimitExceeded)]
    public async Task GetViewAsync_V3SnapshotFaultNeverPresentsPartialDataAsComplete(
        FirewallCommand command,
        SnapshotFault fault)
    {
        var client = new SnapshotFaultClient(command, fault);
        var gateway = new FirewallServiceGateway(client);

        var view = await gateway.GetViewAsync();

        Assert.False(view.ServiceAvailable);
        Assert.Empty(view.Policies);
        Assert.Empty(view.Pending);
        Assert.Contains(client.Requests, request => request.Command == command);
        Assert.DoesNotContain(client.Requests, request => request.Command is
            FirewallCommand.UpsertPolicy or FirewallCommand.RemovePolicy or
            FirewallCommand.EnableEnforcement or FirewallCommand.EmergencyDisable);
    }

    [Fact]
    public async Task Mutation_V3ThenV2TypedEofThenV1_SendsMutationExactlyOnce()
    {
        var client = new LegacyOnlyClient();
        var gateway = new FirewallServiceGateway(client);

        Assert.Equal(FirewallMutationResult.Applied, await gateway.EnableEnforcementAsync());

        Assert.Equal(
            [FirewallProtocolCodec.CurrentVersion, FirewallProtocolCodec.RuntimeProofVersion,
                FirewallProtocolCodec.LegacyVersion],
            client.Requests.Where(request => request.Command == FirewallCommand.GetStatus)
                .Select(request => request.ProtocolVersion));
        var mutation = Assert.Single(client.Requests,
            request => request.Command == FirewallCommand.EnableEnforcement);
        Assert.Equal(FirewallProtocolCodec.LegacyVersion, mutation.ProtocolVersion);
    }

    [Theory]
    [InlineData(NegotiationFault.Timeout)]
    [InlineData(NegotiationFault.MalformedProtocol)]
    [InlineData(NegotiationFault.GenericIo)]
    [InlineData(NegotiationFault.PeerValidation)]
    public async Task Mutation_V2ProbeFaultAfterTypedV3EofDoesNotDowngradeCacheOrReplay(
        NegotiationFault fault)
    {
        var client = new SecondProbeFaultClient(fault);
        var gateway = new FirewallServiceGateway(client);

        Assert.Equal(FirewallMutationResult.ServiceUnavailable, await gateway.EnableEnforcementAsync());
        Assert.Equal(FirewallMutationResult.ServiceUnavailable, await gateway.EmergencyDisableAsync());

        Assert.Equal(
            [FirewallProtocolCodec.CurrentVersion, FirewallProtocolCodec.RuntimeProofVersion,
                FirewallProtocolCodec.CurrentVersion, FirewallProtocolCodec.RuntimeProofVersion],
            client.Requests.Select(request => request.ProtocolVersion));
        Assert.All(client.Requests, request => Assert.Equal(FirewallCommand.GetStatus, request.Command));
    }

    [Theory]
    [InlineData(NegotiationFault.Timeout)]
    [InlineData(NegotiationFault.MalformedProtocol)]
    [InlineData(NegotiationFault.UnsupportedVersionException)]
    [InlineData(NegotiationFault.UnsupportedVersionResponse)]
    [InlineData(NegotiationFault.GenericIo)]
    [InlineData(NegotiationFault.PeerValidation)]
    public async Task Mutation_NonLegacyNegotiationFailureNeverFallsBackCachesOrSendsMutation(
        NegotiationFault fault)
    {
        var client = new NegotiationFaultClient(fault);
        var gateway = new FirewallServiceGateway(client);

        Assert.Equal(FirewallMutationResult.ServiceUnavailable, await gateway.EnableEnforcementAsync());
        Assert.Equal(FirewallMutationResult.ServiceUnavailable, await gateway.EmergencyDisableAsync());

        Assert.Equal(2, client.Requests.Count);
        Assert.All(client.Requests, request =>
        {
            Assert.Equal(FirewallProtocolCodec.CurrentVersion, request.ProtocolVersion);
            Assert.Equal(FirewallCommand.GetStatus, request.Command);
        });
    }

    [Fact]
    public async Task SetPolicyAsync_Success_ReturnsApplied()
    {
        var client = new CapturingClient(request =>
            new FirewallCommandResponse(request.ProtocolVersion, request.RequestId, Success: true));
        var gateway = new FirewallServiceGateway(client);

        var result = await gateway.SetPolicyAsync(new AppFirewallPolicy(@"C:\a.exe", OutboundAction.Block));

        Assert.Equal(FirewallMutationResult.Applied, result);
        Assert.Equal(FirewallCommand.UpsertPolicy, client.LastRequest!.Command);
        Assert.Equal(OutboundAction.Block, client.LastRequest.Policy!.Action);
    }

    [Fact]
    public async Task RemovePolicyAsync_SendsRemoveWithPath()
    {
        var client = new CapturingClient(request =>
            new FirewallCommandResponse(request.ProtocolVersion, request.RequestId, Success: true));
        var gateway = new FirewallServiceGateway(client);

        var result = await gateway.RemovePolicyAsync(@"C:\a.exe");

        Assert.Equal(FirewallMutationResult.Applied, result);
        Assert.Equal(FirewallCommand.RemovePolicy, client.LastRequest!.Command);
        Assert.Equal(@"C:\a.exe", client.LastRequest.ExecutablePath);
    }

    [Fact]
    public async Task EmergencyDisableAsync_SendsEmergencyDisable()
    {
        var client = new CapturingClient(request =>
            new FirewallCommandResponse(request.ProtocolVersion, request.RequestId, Success: true));
        var gateway = new FirewallServiceGateway(client);

        var result = await gateway.EmergencyDisableAsync();

        Assert.Equal(FirewallMutationResult.Applied, result);
        Assert.Equal(FirewallCommand.EmergencyDisable, client.LastRequest!.Command);
    }

    [Fact]
    public async Task EnableEnforcementAsync_SendsEnableEnforcement()
    {
        var client = new CapturingClient(request =>
            new FirewallCommandResponse(request.ProtocolVersion, request.RequestId, Success: true));
        var gateway = new FirewallServiceGateway(client);

        var result = await gateway.EnableEnforcementAsync();

        Assert.Equal(FirewallMutationResult.Applied, result);
        Assert.Equal(FirewallCommand.EnableEnforcement, client.LastRequest!.Command);
    }

    // A machine that cannot filter must not be reported as a retryable rejection: that would
    // invite the operator to believe another attempt would protect them.
    [Fact]
    public async Task EnableEnforcementAsync_NotSupported_MapsToNotSupported()
    {
        var client = new CapturingClient(request =>
            new FirewallCommandResponse(
                request.ProtocolVersion, request.RequestId, Success: false, FirewallProtocolError.NotSupported));
        var gateway = new FirewallServiceGateway(client);

        Assert.Equal(FirewallMutationResult.NotSupported, await gateway.EnableEnforcementAsync());
    }

    [Fact]
    public async Task Mutation_Unauthorized_MapsToUnauthorized()
    {
        var client = new CapturingClient(request =>
            new FirewallCommandResponse(
                request.ProtocolVersion, request.RequestId, Success: false, FirewallProtocolError.Unauthorized));
        var gateway = new FirewallServiceGateway(client);

        Assert.Equal(
            FirewallMutationResult.Unauthorized,
            await gateway.SetPolicyAsync(new AppFirewallPolicy(@"C:\a.exe", OutboundAction.Allow)));
    }

    [Fact]
    public async Task Mutation_ServiceError_MapsToRejected()
    {
        var client = new CapturingClient(request =>
            new FirewallCommandResponse(
                request.ProtocolVersion, request.RequestId, Success: false, FirewallProtocolError.InternalFailure));
        var gateway = new FirewallServiceGateway(client);

        Assert.Equal(
            FirewallMutationResult.Rejected,
            await gateway.RemovePolicyAsync(@"C:\a.exe"));
    }

    [Fact]
    public async Task Mutation_TransportFault_MapsToServiceUnavailable()
    {
        var gateway = new FirewallServiceGateway(new ThrowingClient());

        Assert.Equal(
            FirewallMutationResult.ServiceUnavailable,
            await gateway.EmergencyDisableAsync());
    }

    private sealed class ThrowingClient : IFirewallServiceClient
    {
        public Task<FirewallCommandResponse> SendAsync(
            FirewallCommandRequest request, TimeSpan connectTimeout, CancellationToken cancellationToken = default) =>
            throw new TimeoutException("no service");
    }

    private sealed class CapturingClient : IFirewallServiceClient
    {
        private readonly Func<FirewallCommandRequest, FirewallCommandResponse> _respond;

        public CapturingClient(Func<FirewallCommandRequest, FirewallCommandResponse> respond) => _respond = respond;

        public FirewallCommandRequest? LastRequest { get; private set; }

        public Task<FirewallCommandResponse> SendAsync(
            FirewallCommandRequest request, TimeSpan connectTimeout, CancellationToken cancellationToken = default)
        {
            if (request.Command == FirewallCommand.GetStatus)
            {
                return Task.FromResult(new FirewallCommandResponse(
                    request.ProtocolVersion,
                    request.RequestId,
                    Success: true,
                    Status: new FirewallServiceStatus(
                        OutboundFirewallMode.AuditOnly,
                        EngineSupported: true,
                        EnforcementEnabled: false)));
            }
            LastRequest = request;
            return Task.FromResult(_respond(request));
        }
    }

    private sealed class ScriptedClient : IFirewallServiceClient
    {
        private readonly FirewallServiceStatus _status;
        private readonly IReadOnlyList<(AppFirewallPolicy[] Policies, int? NextOffset)> _pages;
        private readonly IReadOnlyList<(PendingOutboundApp[] Pending, int? NextOffset)> _pendingPages;
        private int _policyPageIndex;
        private int _pendingPageIndex;
        private const string PolicySnapshot = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        private const string PendingSnapshot = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        public List<FirewallCommandRequest> Requests { get; } = [];

        public ScriptedClient(
            FirewallServiceStatus status,
            IReadOnlyList<(AppFirewallPolicy[] Policies, int? NextOffset)> pages,
            IReadOnlyList<(PendingOutboundApp[] Pending, int? NextOffset)>? pendingPages = null)
        {
            _status = status;
            _pages = pages;
            _pendingPages = pendingPages ?? [(Array.Empty<PendingOutboundApp>(), null)];
        }

        public Task<FirewallCommandResponse> SendAsync(
            FirewallCommandRequest request, TimeSpan connectTimeout, CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            var response = request.Command switch
            {
                FirewallCommand.GetStatus => new FirewallCommandResponse(
                    request.ProtocolVersion, request.RequestId, Success: true, Status: _status),
                FirewallCommand.ListPolicies => NextPolicyPage(request),
                FirewallCommand.ListPending => NextPendingPage(request),
                _ => new FirewallCommandResponse(
                    request.ProtocolVersion, request.RequestId, Success: false, FirewallProtocolError.InvalidRequest),
            };
            return Task.FromResult(response);
        }

        private FirewallCommandResponse NextPolicyPage(FirewallCommandRequest request)
        {
            var (policies, nextOffset) = _pages[Math.Min(_policyPageIndex, _pages.Count - 1)];
            _policyPageIndex++;
            return new FirewallCommandResponse(
                request.ProtocolVersion, request.RequestId, Success: true, Policies: policies, NextOffset: nextOffset,
                SnapshotVersion: request.ProtocolVersion == FirewallProtocolCodec.CurrentVersion ? PolicySnapshot : null,
                SnapshotCount: request.ProtocolVersion == FirewallProtocolCodec.CurrentVersion
                    ? _pages.Sum(page => page.Policies.Length)
                    : null);
        }

        private FirewallCommandResponse NextPendingPage(FirewallCommandRequest request)
        {
            var (pending, nextOffset) = _pendingPages[Math.Min(_pendingPageIndex, _pendingPages.Count - 1)];
            _pendingPageIndex++;
            return new FirewallCommandResponse(
                request.ProtocolVersion, request.RequestId, Success: true, Pending: pending, NextOffset: nextOffset,
                SnapshotVersion: request.ProtocolVersion == FirewallProtocolCodec.CurrentVersion ? PendingSnapshot : null,
                SnapshotCount: request.ProtocolVersion == FirewallProtocolCodec.CurrentVersion
                    ? _pendingPages.Sum(page => page.Pending.Length)
                    : null);
        }
    }

    private sealed class LegacyOnlyClient : IFirewallServiceClient
    {
        public List<FirewallCommandRequest> Requests { get; } = [];

        public Task<FirewallCommandResponse> SendAsync(
            FirewallCommandRequest request, TimeSpan connectTimeout, CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            if (request.ProtocolVersion is FirewallProtocolCodec.CurrentVersion
                or FirewallProtocolCodec.RuntimeProofVersion)
            {
                throw new FirewallLegacyPeerClosedException();
            }

            return Task.FromResult(request.Command switch
            {
                FirewallCommand.GetStatus => new FirewallCommandResponse(
                    FirewallProtocolCodec.LegacyVersion,
                    request.RequestId,
                    Success: true,
                    Status: new FirewallServiceStatus(
                        OutboundFirewallMode.Enforcement,
                        EngineSupported: true,
                        // This is the v1 wire response after FirewallProtocolCodec has projected
                        // it to the conservative v2 in-memory representation.
                        EnforcementEnabled: false,
                        EffectiveState: FirewallEnforcementState.Degraded)),
                FirewallCommand.EnableEnforcement => new FirewallCommandResponse(
                    FirewallProtocolCodec.LegacyVersion, request.RequestId, Success: true),
                FirewallCommand.ListPolicies => new FirewallCommandResponse(
                    FirewallProtocolCodec.LegacyVersion, request.RequestId, Success: true, Policies: []),
                FirewallCommand.ListPending => new FirewallCommandResponse(
                    FirewallProtocolCodec.LegacyVersion, request.RequestId, Success: true, Pending: []),
                _ => new FirewallCommandResponse(
                    FirewallProtocolCodec.LegacyVersion,
                    request.RequestId,
                    Success: false,
                    FirewallProtocolError.InvalidRequest),
            });
        }
    }

    private sealed class AlwaysPeerRejectingClient : IFirewallServiceClient
    {
        public List<FirewallCommandRequest> Requests { get; } = [];

        public Task<FirewallCommandResponse> SendAsync(
            FirewallCommandRequest request, TimeSpan connectTimeout, CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            throw new FirewallPeerValidationException();
        }
    }

    private sealed class SecondProbeFaultClient(NegotiationFault fault) : IFirewallServiceClient
    {
        public List<FirewallCommandRequest> Requests { get; } = [];

        public Task<FirewallCommandResponse> SendAsync(
            FirewallCommandRequest request,
            TimeSpan connectTimeout,
            CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            if (request.ProtocolVersion == FirewallProtocolCodec.CurrentVersion)
            {
                throw new FirewallLegacyPeerClosedException();
            }
            return fault switch
            {
                NegotiationFault.Timeout => throw new TimeoutException(),
                NegotiationFault.MalformedProtocol => throw new FirewallProtocolException(
                    FirewallProtocolError.InvalidRequest, "malformed"),
                NegotiationFault.GenericIo => throw new IOException("transport"),
                NegotiationFault.PeerValidation => throw new FirewallPeerValidationException(),
                _ => throw new InvalidOperationException(),
            };
        }
    }

    private sealed class ProbeThenMutationPeerRejectingClient : IFirewallServiceClient
    {
        public List<FirewallCommandRequest> Requests { get; } = [];

        public Task<FirewallCommandResponse> SendAsync(
            FirewallCommandRequest request, TimeSpan connectTimeout, CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            if (request.Command == FirewallCommand.GetStatus)
            {
                return Task.FromResult(new FirewallCommandResponse(
                    request.ProtocolVersion,
                    request.RequestId,
                    Success: true,
                    Status: new FirewallServiceStatus(
                        OutboundFirewallMode.AuditOnly,
                        EngineSupported: true,
                        EnforcementEnabled: false)));
            }
            throw new FirewallPeerValidationException();
        }
    }

    public enum NegotiationFault
    {
        Timeout,
        MalformedProtocol,
        UnsupportedVersionException,
        UnsupportedVersionResponse,
        GenericIo,
        PeerValidation,
    }

    private sealed class NegotiationFaultClient(NegotiationFault fault) : IFirewallServiceClient
    {
        public List<FirewallCommandRequest> Requests { get; } = [];

        public Task<FirewallCommandResponse> SendAsync(
            FirewallCommandRequest request,
            TimeSpan connectTimeout,
            CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            return fault switch
            {
                NegotiationFault.Timeout => throw new TimeoutException(),
                NegotiationFault.MalformedProtocol => throw new FirewallProtocolException(
                    FirewallProtocolError.InvalidRequest, "malformed"),
                NegotiationFault.UnsupportedVersionException => throw new FirewallProtocolException(
                    FirewallProtocolError.UnsupportedVersion, "unsupported"),
                NegotiationFault.UnsupportedVersionResponse => Task.FromResult(new FirewallCommandResponse(
                    request.ProtocolVersion,
                    request.RequestId,
                    Success: false,
                    FirewallProtocolError.UnsupportedVersion)),
                NegotiationFault.GenericIo => throw new IOException("transport"),
                NegotiationFault.PeerValidation => throw new FirewallPeerValidationException(),
                _ => throw new InvalidOperationException(),
            };
        }
    }

    public enum PaginationFault
    {
        FirstPageFailure,
        FirstPageNull,
        IntermediateFailure,
        IntermediateNull,
        NonAdvancing,
        WrongNextOffset,
        EmptyWithNextOffset,
        MaxPagesExhausted,
    }

    public enum SnapshotFault
    {
        MissingToken,
        MissingCount,
        TokenChanges,
        CountChanges,
        DuplicateAcrossPages,
        EarlyTerminal,
        LateTerminal,
        GlobalLimitExceeded,
    }

    private sealed class SnapshotFaultClient(
        FirewallCommand targetCommand,
        SnapshotFault fault) : IFirewallServiceClient
    {
        private const string SnapshotA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        private const string SnapshotB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        private int _targetPage;
        public List<FirewallCommandRequest> Requests { get; } = [];

        public Task<FirewallCommandResponse> SendAsync(
            FirewallCommandRequest request,
            TimeSpan connectTimeout,
            CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            if (request.Command == FirewallCommand.GetStatus)
            {
                return Task.FromResult(new FirewallCommandResponse(
                    request.ProtocolVersion,
                    request.RequestId,
                    Success: true,
                    Status: new FirewallServiceStatus(
                        OutboundFirewallMode.AuditOnly, EngineSupported: true, EnforcementEnabled: false)));
            }
            if (request.Command is not (FirewallCommand.ListPolicies or FirewallCommand.ListPending))
            {
                throw new InvalidOperationException("Unexpected mutation during snapshot read.");
            }
            if (request.Command != targetCommand)
            {
                return Task.FromResult(Page(request, itemIndex: 0, nextOffset: null,
                    snapshotVersion: request.Command == FirewallCommand.ListPolicies ? SnapshotA : SnapshotB,
                    snapshotCount: 0, empty: true));
            }

            var page = _targetPage++;
            var response = fault switch
            {
                SnapshotFault.MissingToken => Page(request, 0, null, null, 1),
                SnapshotFault.MissingCount => Page(request, 0, null, SnapshotA, null),
                SnapshotFault.TokenChanges when page == 0 => Page(request, 0, 1, SnapshotA, 2),
                SnapshotFault.TokenChanges => Page(request, 1, null, SnapshotB, 2),
                SnapshotFault.CountChanges when page == 0 => Page(request, 0, 1, SnapshotA, 2),
                SnapshotFault.CountChanges => Page(request, 1, null, SnapshotA, 3),
                SnapshotFault.DuplicateAcrossPages when page == 0 => Page(request, 0, 1, SnapshotA, 2),
                SnapshotFault.DuplicateAcrossPages => Page(request, 0, null, SnapshotA, 2),
                SnapshotFault.EarlyTerminal => Page(request, 0, null, SnapshotA, 2),
                SnapshotFault.LateTerminal => Page(request, 0, 1, SnapshotA, 1),
                SnapshotFault.GlobalLimitExceeded => Page(
                    request, 0, null, SnapshotA,
                    targetCommand == FirewallCommand.ListPolicies
                        ? FirewallPolicyStore.MaxPolicyCount + 1
                        : PendingOutboundLog.MaxPendingApps + 1),
                _ => throw new InvalidOperationException(),
            };
            return Task.FromResult(response);
        }

        private static FirewallCommandResponse Page(
            FirewallCommandRequest request,
            int itemIndex,
            int? nextOffset,
            string? snapshotVersion,
            int? snapshotCount,
            bool empty = false) =>
            request.Command == FirewallCommand.ListPolicies
                ? new FirewallCommandResponse(
                    request.ProtocolVersion,
                    request.RequestId,
                    Success: true,
                    Policies: empty
                        ? []
                        : [new AppFirewallPolicy($@"C:\apps\policy-{itemIndex}.exe", OutboundAction.Ask)],
                    NextOffset: nextOffset,
                    SnapshotVersion: snapshotVersion,
                    SnapshotCount: snapshotCount)
                : new FirewallCommandResponse(
                    request.ProtocolVersion,
                    request.RequestId,
                    Success: true,
                    Pending: empty
                        ? []
                        :
                        [
                            new PendingOutboundApp(
                                $@"C:\apps\pending-{itemIndex}.exe",
                                "1.2.3.4:443",
                                DateTimeOffset.UnixEpoch,
                                DateTimeOffset.UnixEpoch,
                                1),
                        ],
                    NextOffset: nextOffset,
                    SnapshotVersion: snapshotVersion,
                    SnapshotCount: snapshotCount);
    }

    private sealed class StatusChangesDuringPagesClient(
        FirewallEnforcementState finalState,
        OutboundFirewallMode finalMode) : IFirewallServiceClient
    {
        public int StatusCalls { get; private set; }
        public bool PageWasRead { get; private set; }

        public Task<FirewallCommandResponse> SendAsync(
            FirewallCommandRequest request,
            TimeSpan connectTimeout,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (request.Command == FirewallCommand.GetStatus)
            {
                StatusCalls++;
                var final = PageWasRead && StatusCalls >= 3;
                var state = final ? finalState : FirewallEnforcementState.Active;
                var mode = final ? finalMode : OutboundFirewallMode.Enforcement;
                return Task.FromResult(new FirewallCommandResponse(
                    request.ProtocolVersion,
                    request.RequestId,
                    Success: true,
                    Status: new FirewallServiceStatus(
                        mode,
                        EngineSupported: true,
                        EnforcementEnabled: state == FirewallEnforcementState.Active,
                        EffectiveState: state)));
            }

            PageWasRead = true;
            return Task.FromResult(request.Command switch
            {
                FirewallCommand.ListPolicies => new FirewallCommandResponse(
                    request.ProtocolVersion,
                    request.RequestId,
                    Success: true,
                    Policies: [],
                    SnapshotVersion: new string('A', 64),
                    SnapshotCount: 0),
                FirewallCommand.ListPending => new FirewallCommandResponse(
                    request.ProtocolVersion,
                    request.RequestId,
                    Success: true,
                    Pending: [],
                    SnapshotVersion: new string('B', 64),
                    SnapshotCount: 0),
                _ => throw new InvalidOperationException("Unexpected mutation."),
            });
        }
    }

    private sealed class PaginationFaultClient(
        FirewallCommand targetCommand,
        PaginationFault fault) : IFirewallServiceClient
    {
        private int _targetPage;
        public List<FirewallCommandRequest> Requests { get; } = [];

        public Task<FirewallCommandResponse> SendAsync(
            FirewallCommandRequest request,
            TimeSpan connectTimeout,
            CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            if (request.Command == FirewallCommand.GetStatus)
            {
                return Task.FromResult(new FirewallCommandResponse(
                    request.ProtocolVersion,
                    request.RequestId,
                    Success: true,
                    Status: new FirewallServiceStatus(
                        OutboundFirewallMode.AuditOnly,
                        EngineSupported: true,
                        EnforcementEnabled: false)));
            }
            if (request.Command is not (FirewallCommand.ListPolicies or FirewallCommand.ListPending))
            {
                throw new InvalidOperationException("Unexpected mutation during a read-only view.");
            }
            if (request.Command != targetCommand)
            {
                return Task.FromResult(EmptyPage(request));
            }

            var page = _targetPage++;
            var response = fault switch
            {
                PaginationFault.FirstPageFailure => Failure(request),
                PaginationFault.FirstPageNull => NullPage(request),
                PaginationFault.IntermediateFailure when page > 0 => Failure(request),
                PaginationFault.IntermediateNull when page > 0 => NullPage(request),
                PaginationFault.IntermediateFailure or PaginationFault.IntermediateNull =>
                    ItemPage(request, nextOffset: 1),
                PaginationFault.NonAdvancing => ItemPage(request, nextOffset: request.Offset ?? 0),
                PaginationFault.WrongNextOffset => ItemPage(request, nextOffset: checked((request.Offset ?? 0) + 2)),
                PaginationFault.EmptyWithNextOffset => EmptyPage(request, nextOffset: checked((request.Offset ?? 0) + 1)),
                PaginationFault.MaxPagesExhausted => ItemPage(
                    request, nextOffset: checked((request.Offset ?? 0) + 1)),
                _ => throw new InvalidOperationException(),
            };
            return Task.FromResult(response);
        }

        private static FirewallCommandResponse Failure(FirewallCommandRequest request) =>
            new(request.ProtocolVersion, request.RequestId, Success: false, FirewallProtocolError.InternalFailure);

        private static FirewallCommandResponse NullPage(FirewallCommandRequest request) =>
            new(request.ProtocolVersion, request.RequestId, Success: true);

        private static FirewallCommandResponse EmptyPage(FirewallCommandRequest request, int? nextOffset = null) =>
            request.Command == FirewallCommand.ListPolicies
                ? new(request.ProtocolVersion, request.RequestId, Success: true,
                    Policies: [], NextOffset: nextOffset,
                    SnapshotVersion: request.ProtocolVersion == FirewallProtocolCodec.CurrentVersion
                        ? new string('A', 64) : null,
                    SnapshotCount: request.ProtocolVersion == FirewallProtocolCodec.CurrentVersion
                        ? nextOffset ?? 0 : null)
                : new(request.ProtocolVersion, request.RequestId, Success: true,
                    Pending: [], NextOffset: nextOffset,
                    SnapshotVersion: request.ProtocolVersion == FirewallProtocolCodec.CurrentVersion
                        ? new string('B', 64) : null,
                    SnapshotCount: request.ProtocolVersion == FirewallProtocolCodec.CurrentVersion
                        ? nextOffset ?? 0 : null);

        private static FirewallCommandResponse ItemPage(FirewallCommandRequest request, int nextOffset)
        {
            var index = request.Offset ?? 0;
            return request.Command == FirewallCommand.ListPolicies
                ? new(request.ProtocolVersion, request.RequestId, Success: true,
                    Policies: [new AppFirewallPolicy($@"C:\apps\policy-{index}.exe", OutboundAction.Ask)],
                    NextOffset: nextOffset)
                : new(request.ProtocolVersion, request.RequestId, Success: true,
                    Pending:
                    [
                        new PendingOutboundApp(
                            $@"C:\apps\pending-{index}.exe",
                            "1.2.3.4:443",
                            DateTimeOffset.UnixEpoch,
                            DateTimeOffset.UnixEpoch,
                            1),
                    ],
                    NextOffset: nextOffset);
        }
    }
}
