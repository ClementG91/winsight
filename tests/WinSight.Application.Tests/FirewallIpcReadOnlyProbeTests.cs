using System.Reflection;

using WinSight.Firewall;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class FirewallIpcReadOnlyProbeTests
{
    [Theory]
    [InlineData(FirewallEnforcementState.AuditOnly)]
    [InlineData(FirewallEnforcementState.Active)]
    [InlineData(FirewallEnforcementState.Degraded)]
    public async Task ResponsiveStatusSendsExactlyOneReadAndNoMutation(FirewallEnforcementState state)
    {
        var client = new Client((request, _) => Task.FromResult(Response(request) with
        {
            Status = new(state == FirewallEnforcementState.Active ? OutboundFirewallMode.Enforcement : OutboundFirewallMode.AuditOnly,
                true, state == FirewallEnforcementState.Active, EffectiveState: state),
        }));

        Assert.True(await Run(client));

        AssertReadOnly(Assert.Single(client.Requests));
        Assert.True(client.Token.CanBeCanceled);
        Assert.InRange(client.Timeout, TimeSpan.FromMilliseconds(1), TimeSpan.FromSeconds(10));
    }

    [Theory]
    [InlineData("unsuccessful")]
    [InlineData("missing-status")]
    [InlineData("wrong-request")]
    [InlineData("wrong-version")]
    [InlineData("error")]
    [InlineData("unknown-mode")]
    [InlineData("unknown-state")]
    [InlineData("negative-loss")]
    [InlineData("active-audit")]
    [InlineData("active-disabled")]
    [InlineData("enabled-unsupported")]
    public async Task InvalidStatusCannotProveAvailability(string scenario)
    {
        var client = new Client((request, _) => Task.FromResult(scenario switch
        {
            "unsuccessful" => Response(request) with { Success = false },
            "missing-status" => Response(request) with { Status = null },
            "wrong-request" => Response(request) with { RequestId = Guid.NewGuid() },
            "wrong-version" => Response(request) with { ProtocolVersion = request.ProtocolVersion - 1 },
            "error" => Response(request) with { Error = FirewallProtocolError.InternalFailure },
            "unknown-mode" => Response(request) with { Status = new((OutboundFirewallMode)999, true, false) },
            "unknown-state" => Response(request) with { Status = new(OutboundFirewallMode.AuditOnly, true, false, EffectiveState: (FirewallEnforcementState)999) },
            "negative-loss" => Response(request) with { Status = new(OutboundFirewallMode.AuditOnly, true, false, UnrecordedApps: -1) },
            "active-audit" => Response(request) with { Status = new(OutboundFirewallMode.AuditOnly, true, true, EffectiveState: FirewallEnforcementState.Active) },
            "active-disabled" => Response(request) with { Status = new(OutboundFirewallMode.Enforcement, true, false, EffectiveState: FirewallEnforcementState.Active) },
            "enabled-unsupported" => Response(request) with { Status = new(OutboundFirewallMode.Enforcement, false, true, EffectiveState: FirewallEnforcementState.Active) },
            _ => throw new InvalidOperationException(),
        }));

        Assert.False(await Run(client));
        AssertReadOnly(Assert.Single(client.Requests));
    }

    [Theory]
    [InlineData("timeout")]
    [InlineData("io")]
    [InlineData("peer")]
    [InlineData("protocol")]
    [InlineData("access")]
    public async Task ExpectedTransportFailuresAreUnavailableWithoutRetry(string scenario)
    {
        var client = new Client((_, _) => throw scenario switch
        {
            "timeout" => new TimeoutException(),
            "io" => new IOException(),
            "peer" => new FirewallPeerValidationException(),
            "protocol" => new FirewallProtocolException(FirewallProtocolError.InvalidRequest, "fixture"),
            "access" => new UnauthorizedAccessException(),
            _ => new InvalidOperationException(),
        });

        Assert.False(await Run(client));
        AssertReadOnly(Assert.Single(client.Requests));
    }

    [Fact]
    public async Task CallerCancellationIsPreserved()
    {
        using var cancellation = new CancellationTokenSource();
        var client = new Client((_, token) =>
        {
            cancellation.Cancel();
            token.ThrowIfCancellationRequested();
            throw new InvalidOperationException("cancellation did not propagate");
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Run(client, cancellation.Token));
        AssertReadOnly(Assert.Single(client.Requests));
    }

    [Fact]
    public async Task OverallDeadlineCancelsAConnectedRead()
    {
        using var abort = new CancellationTokenSource();
        var client = new Client(async (_, token) =>
        {
            using var fixtureLifetime = CancellationTokenSource.CreateLinkedTokenSource(token, abort.Token);
            await Task.Delay(Timeout.InfiniteTimeSpan, fixtureLifetime.Token);
            throw new InvalidOperationException("the read must be cancelled");
        });

        var attempt = Run(client);
        Exception? primary = null;
        Exception? cleanupFailure = null;
        try
        {
            Assert.False(await attempt.WaitAsync(TimeSpan.FromSeconds(30)));
            Assert.True(client.Token.IsCancellationRequested);
            AssertReadOnly(Assert.Single(client.Requests));
        }
        catch (Exception failure)
        {
            primary = failure;
        }
        finally
        {
            abort.Cancel();
            try
            {
                await attempt.WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (Exception cleanup)
            {
                cleanupFailure = cleanup;
            }
        }
        if (primary is not null && cleanupFailure is not null && !ReferenceEquals(primary, cleanupFailure))
        {
            throw new AggregateException("Read-only probe fixture cleanup failed.", primary, cleanupFailure);
        }
        if ((primary ?? cleanupFailure) is { } failureToReport)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failureToReport).Throw();
        }
    }

    private static void AssertReadOnly(FirewallCommandRequest request)
    {
        Assert.Equal(FirewallCommand.GetStatus, request.Command);
        Assert.Equal(FirewallProtocolCodec.CurrentVersion, request.ProtocolVersion);
        Assert.NotEqual(Guid.Empty, request.RequestId);
        Assert.Null(request.Policy);
        Assert.Null(request.ExecutablePath);
        Assert.Null(request.Offset);
        Assert.Null(request.Limit);
        Assert.Null(request.SnapshotVersion);
    }

    // One bridge permits freezing tests before the additive API exists. API absence is
    // infrastructure failure, NEVER the qualifying behavioral RED from the old observer.
    private static Task<bool> Run(IFirewallServiceClient client, CancellationToken token = default)
    {
        var type = typeof(FirewallIpcSelfTest).Assembly.GetType("WinSight.Application.FirewallIpcReadOnlyProbe", throwOnError: true)!;
        var method = type.GetMethod("RunAsync", BindingFlags.Public | BindingFlags.Static,
            [typeof(IFirewallServiceClient), typeof(CancellationToken)])
            ?? throw new MissingMethodException(type.FullName, "RunAsync");
        try
        {
            return (Task<bool>)method.Invoke(null, [client, token])!;
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    private static FirewallCommandResponse Response(FirewallCommandRequest request) =>
        new(request.ProtocolVersion, request.RequestId, true,
            Status: new(OutboundFirewallMode.AuditOnly, true, false));

    private sealed class Client(Func<FirewallCommandRequest, CancellationToken, Task<FirewallCommandResponse>> send)
        : IFirewallServiceClient
    {
        internal List<FirewallCommandRequest> Requests { get; } = [];
        internal TimeSpan Timeout { get; private set; }
        internal CancellationToken Token { get; private set; }

        public Task<FirewallCommandResponse> SendAsync(FirewallCommandRequest request,
            TimeSpan connectTimeout, CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            Timeout = connectTimeout;
            Token = cancellationToken;
            return send(request, cancellationToken);
        }
    }
}
