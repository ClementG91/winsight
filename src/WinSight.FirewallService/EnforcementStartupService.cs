using System.ComponentModel;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

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
    private readonly EnforcementCoordinator _coordinator;
    private readonly ILogger<EnforcementStartupService> _logger;

    public EnforcementStartupService(EnforcementCoordinator coordinator, ILogger<EnforcementStartupService> logger)
    {
        _coordinator = coordinator ?? throw new ArgumentNullException(nameof(coordinator));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
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
}
