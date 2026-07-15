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
            LastRequest = request;
            return Task.FromResult(_respond(request));
        }
    }

    private sealed class ScriptedClient : IFirewallServiceClient
    {
        private readonly FirewallServiceStatus _status;
        private readonly IReadOnlyList<(AppFirewallPolicy[] Policies, int? NextOffset)> _pages;
        private int _pageIndex;

        public ScriptedClient(
            FirewallServiceStatus status,
            IReadOnlyList<(AppFirewallPolicy[] Policies, int? NextOffset)> pages)
        {
            _status = status;
            _pages = pages;
        }

        public Task<FirewallCommandResponse> SendAsync(
            FirewallCommandRequest request, TimeSpan connectTimeout, CancellationToken cancellationToken = default)
        {
            var response = request.Command switch
            {
                FirewallCommand.GetStatus => new FirewallCommandResponse(
                    request.ProtocolVersion, request.RequestId, Success: true, Status: _status),
                FirewallCommand.ListPolicies => NextPage(request),
                _ => new FirewallCommandResponse(
                    request.ProtocolVersion, request.RequestId, Success: false, FirewallProtocolError.InvalidRequest),
            };
            return Task.FromResult(response);
        }

        private FirewallCommandResponse NextPage(FirewallCommandRequest request)
        {
            var (policies, nextOffset) = _pages[Math.Min(_pageIndex, _pages.Count - 1)];
            _pageIndex++;
            return new FirewallCommandResponse(
                request.ProtocolVersion, request.RequestId, Success: true, Policies: policies, NextOffset: nextOffset);
        }
    }
}
