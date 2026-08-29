using System.ComponentModel;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WinSight.Firewall;

namespace WinSight.FirewallService;

/// <summary>
/// At service start, re-applies the stored Block policies to WFP. WinSight's WFP filters
/// are owned by one dynamic session (removed when the service exits, including a crash), so the
/// service reinstalls them on every boot. Enforcement rebuilds and verifies the exact enabled-block set;
/// AuditOnly removes all WinSight-owned WFP objects. The host registers it only after trusted
/// Enforcement mode is observed; the coordinator revalidates storage before use. A failure is logged and never
/// crashes the service, so the pipe endpoint still comes up.
/// </summary>
public sealed partial class EnforcementStartupService : IHostedService
{
    /// <summary>How long to wait for the endpoint before refusing to arm.</summary>
    /// <remarks>
    /// Generous: opening a named pipe is immediate on a healthy machine, so anything approaching
    /// this bound means the name is held by somebody else and the wait is going to fail anyway.
    /// </remarks>
    private static readonly TimeSpan EndpointReadyTimeout = TimeSpan.FromSeconds(15);

    private readonly EnforcementCoordinator _coordinator;
    private readonly ILogger<EnforcementStartupService> _logger;
    private readonly IFirewallServiceReadiness? _readiness;

    public EnforcementStartupService(
        EnforcementCoordinator coordinator,
        ILogger<EnforcementStartupService> logger,
        IFirewallServiceReadiness? readiness = null)
    {
        _coordinator = coordinator ?? throw new ArgumentNullException(nameof(coordinator));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _readiness = readiness;
    }

    /// <summary>
    /// Waits for the command endpoint to be listening, then re-applies the stored block policies.
    /// </summary>
    /// <remarks>
    /// <b>The order is the security property.</b> This used to be registered before the pipe worker,
    /// so filters were installed and only afterwards did the listener try to claim its name. An
    /// unprivileged caller who owns <c>\.\pipe\WinSightirewall</c> first makes that claim fail,
    /// the host stops, and because the WFP session is dynamic BFE destroys everything just
    /// installed. The squatter therefore got a loop of "filters applied, then immediately removed" -
    /// worse than never arming, because the machine spent the interval believing it was protected.
    ///
    /// Waiting on readiness closes it: no filter is installed until the endpoint is proven live. If
    /// readiness does not arrive, enforcement is simply not applied and the service says so, which
    /// leaves the machine unfiltered rather than intermittently filtered.
    /// </remarks>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!await EndpointIsListeningAsync(cancellationToken).ConfigureAwait(false))
        {
            LogEndpointUnavailable();
            return;
        }

        LogApplying();
        try
        {
            await _coordinator.ApplyBlocksAsync(cancellationToken).ConfigureAwait(false);
            LogApplied();
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidDataException or IOException)
        {
            LogFault();
        }
    }

    private async Task<bool> EndpointIsListeningAsync(CancellationToken cancellationToken)
    {
        if (_readiness is null)
        {
            // No readiness signal to wait on (a test host, or a listener that does not expose one).
            // Behave exactly as before rather than refusing to arm on a technicality.
            return true;
        }
        try
        {
            await _readiness.Ready
                .WaitAsync(EndpointReadyTimeout, cancellationToken)
                .ConfigureAwait(false);
            return true;
        }
        catch (Exception ex) when (ex is TimeoutException or OperationCanceledException)
        {
            return false;
        }
        catch (Exception)
        {
            // The listener faulted before it ever announced readiness. The worker reports that
            // failure and stops the host; nothing here should install a filter on the way out.
            return false;
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        // Hosted services stop in reverse registration order, so the pipe and observer are already
        // down when this first-registered service runs. Dispose the authority before SCM can report
        // the service stopped: closing its dynamic WFP session is the graceful-stop cleanup. Host
        // disposal calls it again later; EnforcementCoordinator disposal is deliberately idempotent.
        await _coordinator.DisposeAsync().AsTask().WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "[FW_STARTUP_APPLY_BEGIN] Applying stored block policies.")]
    private partial void LogApplying();

    [LoggerMessage(Level = LogLevel.Information, Message = "[FW_STARTUP_APPLY_OK] Stored block policies applied.")]
    private partial void LogApplied();

    [LoggerMessage(Level = LogLevel.Error, Message = "[FW_STARTUP_APPLY_FAILED] Stored block policy application failed; the service continues in a degraded state.")]
    private partial void LogFault();

    [LoggerMessage(Level = LogLevel.Error,
        Message = "[FW_STARTUP_ENDPOINT_UNAVAILABLE] The command endpoint never came up; no filter was installed.")]
    private partial void LogEndpointUnavailable();
}
