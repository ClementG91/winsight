using WinSight.Firewall;
using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// The IPC self-test reports what capability the authenticated pipe grants the current caller,
/// without changing machine state. It exists so the multi-user IPC boundary can be exercised on a VM
/// under real elevated / unelevated / standard-user tokens: an unprivileged caller must be able to
/// read status but be refused a mutation, and only a privileged caller may mutate.
/// </summary>
public sealed class FirewallIpcSelfTestTests
{
    [Fact]
    public async Task ServiceUnreachable_ReportsServiceUnavailable_AndSendsNoMutation()
    {
        var client = new RecordingClient(
            _ => throw new InvalidOperationException("an unreachable service is never asked to mutate"),
            readReachable: false);
        var gateway = new FirewallServiceGateway(client);

        var result = await FirewallIpcSelfTest.RunAsync(gateway);

        Assert.Equal(IpcSelfTestOutcome.ServiceUnavailable, result.Outcome);
        Assert.False(result.ServiceAvailable);
        Assert.Null(result.MutationProbe);
        Assert.DoesNotContain(client.MutationRequests, _ => true);
    }

    [Fact]
    public async Task ReadSucceeds_MutationRefused_ReportsCanReadOnly()
    {
        var client = new RecordingClient(request => request.Command == FirewallCommand.RemovePolicy
            ? Fail(request, FirewallProtocolError.Unauthorized)
            : throw new InvalidOperationException("only RemovePolicy is a mutation here"));
        var gateway = new FirewallServiceGateway(client);

        var result = await FirewallIpcSelfTest.RunAsync(gateway);

        Assert.Equal(IpcSelfTestOutcome.CanReadOnly, result.Outcome);
        Assert.True(result.ServiceAvailable);
        Assert.Equal(FirewallMutationResult.Unauthorized, result.MutationProbe);
    }

    [Fact]
    public async Task ReadSucceeds_MutationAccepted_ReportsCanMutate()
    {
        var client = new RecordingClient(request => request.Command == FirewallCommand.RemovePolicy
            ? Success(request)
            : throw new InvalidOperationException("only RemovePolicy is a mutation here"));
        var gateway = new FirewallServiceGateway(client);

        var result = await FirewallIpcSelfTest.RunAsync(gateway);

        Assert.Equal(IpcSelfTestOutcome.CanMutate, result.Outcome);
        Assert.Equal(FirewallMutationResult.Applied, result.MutationProbe);
    }

    // The safety invariant: a diagnostic must never send a mutation to a live-armed machine, even a
    // no-op one, because a RemovePolicy on an armed machine reconciles WFP. When enforcement is
    // Active, the probe reads only and reports that the mutation leg was deliberately skipped.
    [Fact]
    public async Task EnforcementActive_SkipsMutationEntirely()
    {
        var client = new RecordingClient(
            _ => throw new InvalidOperationException("no mutation may be sent to an armed machine"),
            effectiveState: FirewallEnforcementState.Active);
        var gateway = new FirewallServiceGateway(client);

        var result = await FirewallIpcSelfTest.RunAsync(gateway);

        Assert.Equal(IpcSelfTestOutcome.ReadableMutateSkipped, result.Outcome);
        Assert.True(result.ServiceAvailable);
        Assert.Null(result.MutationProbe);
        Assert.Empty(client.MutationRequests);
    }

    // The mutation probe must target a path that can never be a real policed executable, so that on
    // an authorized caller it removes nothing.
    [Fact]
    public async Task MutationProbe_TargetsTheInertProbePath()
    {
        var client = new RecordingClient(request => request.Command == FirewallCommand.RemovePolicy
            ? Fail(request, FirewallProtocolError.Unauthorized)
            : Success(request));
        var gateway = new FirewallServiceGateway(client);

        await FirewallIpcSelfTest.RunAsync(gateway);

        var mutation = Assert.Single(client.MutationRequests);
        Assert.Equal(FirewallCommand.RemovePolicy, mutation.Command);
        Assert.Equal(FirewallIpcSelfTest.ProbePath, mutation.ExecutablePath);
    }

    private static FirewallCommandResponse Success(FirewallCommandRequest request) =>
        new(request.ProtocolVersion, request.RequestId, Success: true);

    private static FirewallCommandResponse Fail(FirewallCommandRequest request, FirewallProtocolError error) =>
        new(request.ProtocolVersion, request.RequestId, Success: false, error);

    /// <summary>
    /// Answers reads (GetStatus/ListPolicies/ListPending) with a settled, empty, available service,
    /// and delegates every mutation to the injected responder while recording it. A mutation the
    /// responder is not meant to see is a test failure, which is how the armed-machine case proves no
    /// mutation was sent.
    /// </summary>
    private sealed class RecordingClient(
        Func<FirewallCommandRequest, FirewallCommandResponse> onMutation,
        FirewallEnforcementState effectiveState = FirewallEnforcementState.AuditOnly,
        bool readReachable = true) : IFirewallServiceClient
    {
        public List<FirewallCommandRequest> MutationRequests { get; } = [];

        public Task<FirewallCommandResponse> SendAsync(
            FirewallCommandRequest request, TimeSpan connectTimeout, CancellationToken cancellationToken = default)
        {
            if (!readReachable)
            {
                throw new TimeoutException("no service");
            }
            switch (request.Command)
            {
                case FirewallCommand.GetStatus:
                    return Task.FromResult(new FirewallCommandResponse(
                        request.ProtocolVersion, request.RequestId, Success: true,
                        Status: new FirewallServiceStatus(
                            OutboundFirewallMode.AuditOnly,
                            EngineSupported: true,
                            EnforcementEnabled: false,
                            EffectiveState: effectiveState)));
                case FirewallCommand.ListPolicies:
                    return Task.FromResult(new FirewallCommandResponse(
                        request.ProtocolVersion, request.RequestId, Success: true,
                        Policies: [], NextOffset: null, SnapshotVersion: new string('A', 64), SnapshotCount: 0));
                case FirewallCommand.ListPending:
                    return Task.FromResult(new FirewallCommandResponse(
                        request.ProtocolVersion, request.RequestId, Success: true,
                        Pending: [], NextOffset: null, SnapshotVersion: new string('B', 64), SnapshotCount: 0));
                default:
                    MutationRequests.Add(request);
                    return Task.FromResult(onMutation(request));
            }
        }
    }
}
