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
        Assert.True(client.StatusCalls >= 2);
    }

    [Fact]
    public async Task GetViewAsync_EmptyResponse_IsUnavailableAfterExactlyOneV3Request()
    {
        var client = new EmptyResponseClient();
        var gateway = new FirewallServiceGateway(client);

        var view = await gateway.GetViewAsync();

        Assert.False(view.ServiceAvailable);
        var request = Assert.Single(client.Requests);
        Assert.Equal(FirewallProtocolCodec.CurrentVersion, request.ProtocolVersion);
        Assert.Equal(FirewallCommand.GetStatus, request.Command);
        Assert.False(view.EnforcementEnabled);
    }

    [Fact]
    public async Task TransientSaturationEof_IsV3OnlyOnEveryCallAndNeverCachesDowngrade()
    {
        var client = new EmptyResponseClient();
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
    public async Task EnableEnforcementAsync_EmptyResponse_IsUnavailableWithoutAnyDowngradeOrReplay()
    {
        var client = new EmptyResponseClient();
        var gateway = new FirewallServiceGateway(client);

        var result = await gateway.EnableEnforcementAsync();

        Assert.Equal(FirewallMutationResult.ServiceUnavailable, result);
        var request = Assert.Single(client.Requests);
        Assert.Equal(FirewallProtocolCodec.CurrentVersion, request.ProtocolVersion);
        Assert.Equal(FirewallCommand.EnableEnforcement, request.Command);
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
    public async Task Mutation_PeerValidationFailure_SendsExactlyOneV3Mutation()
    {
        var client = new AlwaysPeerRejectingClient();
        var gateway = new FirewallServiceGateway(client);

        var result = await gateway.EnableEnforcementAsync();

        Assert.Equal(FirewallMutationResult.ServiceUnavailable, result);
        var request = Assert.Single(client.Requests);
        Assert.Equal(FirewallProtocolCodec.CurrentVersion, request.ProtocolVersion);
        Assert.Equal(FirewallCommand.EnableEnforcement, request.Command);
    }

    [Fact]
    public async Task Mutation_PeerValidationFailure_IsNeverRetriedOrDowngraded()
    {
        var client = new MutationPeerRejectingClient();
        var gateway = new FirewallServiceGateway(client);

        var result = await gateway.EmergencyDisableAsync();

        Assert.Equal(FirewallMutationResult.ServiceUnavailable, result);
        var request = Assert.Single(client.Requests);
        Assert.Equal(FirewallProtocolCodec.CurrentVersion, request.ProtocolVersion);
        Assert.Equal(FirewallCommand.EmergencyDisable, request.Command);
        Assert.Equal(1, client.Requests.Count(request => request.Command == FirewallCommand.EmergencyDisable));
    }

    [Theory]
    [InlineData(FirewallEnvelopeFault.ResponseV1)]
    [InlineData(FirewallEnvelopeFault.ResponseV2)]
    [InlineData(FirewallEnvelopeFault.WrongRequestId)]
    public async Task GetViewAsync_RejectsStatusResponseThatViolatesTheV3Envelope(
        FirewallEnvelopeFault fault)
    {
        var client = new EnvelopeFaultClient(FirewallCommand.GetStatus, fault);
        var gateway = new FirewallServiceGateway(client);

        var view = await gateway.GetViewAsync();

        Assert.False(view.ServiceAvailable);
        Assert.NotEmpty(client.Requests);
        Assert.All(client.Requests, request =>
            Assert.Equal(FirewallProtocolCodec.CurrentVersion, request.ProtocolVersion));
    }

    [Theory]
    [InlineData(FirewallCommand.ListPolicies)]
    [InlineData(FirewallCommand.ListPending)]
    public async Task GetViewAsync_RejectsNonV3ListResponseEvenWhenItLooksComplete(
        FirewallCommand command)
    {
        var client = new EnvelopeFaultClient(command, FirewallEnvelopeFault.ResponseV1);
        var gateway = new FirewallServiceGateway(client);

        var view = await gateway.GetViewAsync();

        Assert.False(view.ServiceAvailable);
        Assert.Contains(client.Requests, request => request.Command == command);
        Assert.All(client.Requests, request =>
            Assert.Equal(FirewallProtocolCodec.CurrentVersion, request.ProtocolVersion));
    }

    [Theory]
    [InlineData(FirewallEnvelopeFault.ResponseV1)]
    [InlineData(FirewallEnvelopeFault.ResponseV2)]
    [InlineData(FirewallEnvelopeFault.WrongRequestId)]
    public async Task Mutation_RejectsSuccessfulResponseThatViolatesTheV3Envelope(
        FirewallEnvelopeFault fault)
    {
        var client = new EnvelopeFaultClient(FirewallCommand.EmergencyDisable, fault);
        var gateway = new FirewallServiceGateway(client);

        var result = await gateway.EmergencyDisableAsync();

        Assert.Equal(FirewallMutationResult.ServiceUnavailable, result);
        var request = Assert.Single(client.Requests);
        Assert.Equal(FirewallProtocolCodec.CurrentVersion, request.ProtocolVersion);
        Assert.Equal(FirewallCommand.EmergencyDisable, request.Command);
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
        var targetRequests = client.Requests.Where(request => request.Command == command).ToArray();
        var expectedCount = fault switch
        {
            PaginationFault.IntermediateFailure or PaginationFault.IntermediateNull => 2,
            PaginationFault.MaxPagesExhausted => command == FirewallCommand.ListPolicies
                ? (FirewallPolicyStore.MaxPolicyCount / FirewallProtocolCodec.MaxPoliciesPerMessage) + 4
                : (PendingOutboundLog.MaxPendingApps / FirewallProtocolCodec.MaxPoliciesPerMessage) + 4,
            _ => 1,
        };
        Assert.Equal(expectedCount, targetRequests.Length);
        Assert.Equal(
            Enumerable.Range(0, expectedCount),
            targetRequests.Select(request => request.Offset!.Value));
        Assert.All(targetRequests, request =>
            Assert.Equal(FirewallProtocolCodec.CurrentVersion, request.ProtocolVersion));
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

    [Theory]
    [InlineData(V3TransportFault.Timeout)]
    [InlineData(V3TransportFault.MalformedProtocol)]
    [InlineData(V3TransportFault.UnsupportedVersionException)]
    [InlineData(V3TransportFault.UnsupportedVersionResponse)]
    [InlineData(V3TransportFault.GenericIo)]
    [InlineData(V3TransportFault.PeerValidation)]
    public async Task Mutation_V3FailureNeverFallsBackCachesOrReplays(
        V3TransportFault fault)
    {
        var client = new V3TransportFaultClient(fault);
        var gateway = new FirewallServiceGateway(client);

        var expected = fault == V3TransportFault.UnsupportedVersionResponse
            ? FirewallMutationResult.Rejected
            : FirewallMutationResult.ServiceUnavailable;
        Assert.Equal(expected, await gateway.EnableEnforcementAsync());
        Assert.Equal(expected, await gateway.EmergencyDisableAsync());

        Assert.Equal(2, client.Requests.Count);
        Assert.Collection(client.Requests,
            request =>
            {
                Assert.Equal(FirewallProtocolCodec.CurrentVersion, request.ProtocolVersion);
                Assert.Equal(FirewallCommand.EnableEnforcement, request.Command);
            },
            request =>
            {
                Assert.Equal(FirewallProtocolCodec.CurrentVersion, request.ProtocolVersion);
                Assert.Equal(FirewallCommand.EmergencyDisable, request.Command);
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

    [Fact]
    public async Task GetViewAsync_PipeAccessDenied_MapsToUnavailable()
    {
        var gateway = new FirewallServiceGateway(
            new FaultingClient(new UnauthorizedAccessException("pipe ACL denied the caller")));

        var view = await gateway.GetViewAsync();

        Assert.False(view.ServiceAvailable);
        Assert.Equal(FirewallEnforcementState.AuditOnly, view.EffectiveState);
    }

    [Fact]
    public async Task Mutation_PipeAccessDenied_MapsToServiceUnavailable()
    {
        var gateway = new FirewallServiceGateway(
            new FaultingClient(new UnauthorizedAccessException("pipe ACL denied the caller")));

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

    private sealed class FaultingClient(Exception failure) : IFirewallServiceClient
    {
        public Task<FirewallCommandResponse> SendAsync(
            FirewallCommandRequest request, TimeSpan connectTimeout, CancellationToken cancellationToken = default) =>
            Task.FromException<FirewallCommandResponse>(failure);
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
                SnapshotVersion: PolicySnapshot,
                SnapshotCount: _pages.Sum(page => page.Policies.Length));
        }

        private FirewallCommandResponse NextPendingPage(FirewallCommandRequest request)
        {
            var (pending, nextOffset) = _pendingPages[Math.Min(_pendingPageIndex, _pendingPages.Count - 1)];
            _pendingPageIndex++;
            return new FirewallCommandResponse(
                request.ProtocolVersion, request.RequestId, Success: true, Pending: pending, NextOffset: nextOffset,
                SnapshotVersion: PendingSnapshot,
                SnapshotCount: _pendingPages.Sum(page => page.Pending.Length));
        }
    }

    private sealed class EmptyResponseClient : IFirewallServiceClient
    {
        public List<FirewallCommandRequest> Requests { get; } = [];

        public Task<FirewallCommandResponse> SendAsync(
            FirewallCommandRequest request, TimeSpan connectTimeout, CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            throw new FirewallLegacyPeerClosedException();
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

    public enum FirewallEnvelopeFault
    {
        ResponseV1,
        ResponseV2,
        WrongRequestId,
    }

    private sealed class EnvelopeFaultClient(
        FirewallCommand faultedCommand,
        FirewallEnvelopeFault fault) : IFirewallServiceClient
    {
        public List<FirewallCommandRequest> Requests { get; } = [];

        public Task<FirewallCommandResponse> SendAsync(
            FirewallCommandRequest request,
            TimeSpan connectTimeout,
            CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            var isFaulted = request.Command == faultedCommand;
            var responseVersion = isFaulted
                ? fault switch
                {
                    FirewallEnvelopeFault.ResponseV1 => FirewallProtocolCodec.LegacyVersion,
                    FirewallEnvelopeFault.ResponseV2 => FirewallProtocolCodec.RuntimeProofVersion,
                    _ => FirewallProtocolCodec.CurrentVersion,
                }
                : FirewallProtocolCodec.CurrentVersion;
            var responseRequestId = isFaulted && fault == FirewallEnvelopeFault.WrongRequestId
                ? Guid.NewGuid()
                : request.RequestId;

            return Task.FromResult(request.Command switch
            {
                FirewallCommand.GetStatus => new FirewallCommandResponse(
                    responseVersion, responseRequestId, Success: true,
                    Status: new FirewallServiceStatus(
                        OutboundFirewallMode.AuditOnly, EngineSupported: true, EnforcementEnabled: false)),
                FirewallCommand.ListPolicies => new FirewallCommandResponse(
                    responseVersion, responseRequestId, Success: true, Policies: [],
                    SnapshotVersion: new string('A', 64),
                    SnapshotCount: 0),
                FirewallCommand.ListPending => new FirewallCommandResponse(
                    responseVersion, responseRequestId, Success: true, Pending: [],
                    SnapshotVersion: new string('B', 64),
                    SnapshotCount: 0),
                _ => new FirewallCommandResponse(responseVersion, responseRequestId, Success: true),
            });
        }
    }

    private sealed class MutationPeerRejectingClient : IFirewallServiceClient
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

    public enum V3TransportFault
    {
        Timeout,
        MalformedProtocol,
        UnsupportedVersionException,
        UnsupportedVersionResponse,
        GenericIo,
        PeerValidation,
    }

    private sealed class V3TransportFaultClient(V3TransportFault fault) : IFirewallServiceClient
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
                V3TransportFault.Timeout => throw new TimeoutException(),
                V3TransportFault.MalformedProtocol => throw new FirewallProtocolException(
                    FirewallProtocolError.InvalidRequest, "malformed"),
                V3TransportFault.UnsupportedVersionException => throw new FirewallProtocolException(
                    FirewallProtocolError.UnsupportedVersion, "unsupported"),
                V3TransportFault.UnsupportedVersionResponse => Task.FromResult(new FirewallCommandResponse(
                    request.ProtocolVersion,
                    request.RequestId,
                    Success: false,
                    FirewallProtocolError.UnsupportedVersion)),
                V3TransportFault.GenericIo => throw new IOException("transport"),
                V3TransportFault.PeerValidation => throw new FirewallPeerValidationException(),
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
                var final = PageWasRead && StatusCalls >= 2;
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
                    ItemPage(request, nextOffset: 1, snapshotCount: 2),
                PaginationFault.NonAdvancing => ItemPage(
                    request, nextOffset: request.Offset ?? 0, snapshotCount: 2),
                PaginationFault.WrongNextOffset => ItemPage(
                    request, nextOffset: checked((request.Offset ?? 0) + 2), snapshotCount: 3),
                PaginationFault.EmptyWithNextOffset => EmptyPage(
                    request, nextOffset: checked((request.Offset ?? 0) + 1), snapshotCount: 1),
                PaginationFault.MaxPagesExhausted => ItemPage(
                    request,
                    nextOffset: checked((request.Offset ?? 0) + 1),
                    snapshotCount: MaximumPages(request.Command) + 1),
                _ => throw new InvalidOperationException(),
            };
            return Task.FromResult(response);
        }

        private static FirewallCommandResponse Failure(FirewallCommandRequest request) =>
            new(request.ProtocolVersion, request.RequestId, Success: false, FirewallProtocolError.InternalFailure);

        private static FirewallCommandResponse NullPage(FirewallCommandRequest request) =>
            new(request.ProtocolVersion, request.RequestId, Success: true);

        private static FirewallCommandResponse EmptyPage(
            FirewallCommandRequest request,
            int? nextOffset = null,
            int snapshotCount = 0) =>
            request.Command == FirewallCommand.ListPolicies
                ? new(request.ProtocolVersion, request.RequestId, Success: true,
                    Policies: [], NextOffset: nextOffset,
                    SnapshotVersion: new string('A', 64),
                    SnapshotCount: snapshotCount)
                : new(request.ProtocolVersion, request.RequestId, Success: true,
                    Pending: [], NextOffset: nextOffset,
                    SnapshotVersion: new string('B', 64),
                    SnapshotCount: snapshotCount);

        private static FirewallCommandResponse ItemPage(
            FirewallCommandRequest request,
            int nextOffset,
            int snapshotCount)
        {
            var index = request.Offset ?? 0;
            return request.Command == FirewallCommand.ListPolicies
                ? new(request.ProtocolVersion, request.RequestId, Success: true,
                    Policies: [new AppFirewallPolicy($@"C:\apps\policy-{index}.exe", OutboundAction.Ask)],
                    NextOffset: nextOffset,
                    SnapshotVersion: new string('A', 64),
                    SnapshotCount: snapshotCount)
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
                    NextOffset: nextOffset,
                    SnapshotVersion: new string('B', 64),
                    SnapshotCount: snapshotCount);
        }

        private static int MaximumPages(FirewallCommand command) => command == FirewallCommand.ListPolicies
            ? (FirewallPolicyStore.MaxPolicyCount / FirewallProtocolCodec.MaxPoliciesPerMessage) + 4
            : (PendingOutboundLog.MaxPendingApps / FirewallProtocolCodec.MaxPoliciesPerMessage) + 4;
    }
}
