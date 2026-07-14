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

    private sealed class ThrowingClient : IFirewallServiceClient
    {
        public Task<FirewallCommandResponse> SendAsync(
            FirewallCommandRequest request, TimeSpan connectTimeout, CancellationToken cancellationToken = default) =>
            throw new TimeoutException("no service");
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
