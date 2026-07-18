using System.ComponentModel;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WinSight.FirewallService;

/// <summary>
/// At service start, re-applies the stored Block policies to WFP. WinSight's WFP filters
/// are non-persistent (removed on reboot), so the service reinstalls them on every boot
/// at service startup. Enforcement rebuilds and verifies the exact enabled-block set;
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

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    [LoggerMessage(Level = LogLevel.Information, Message = "[FW_STARTUP_APPLY_BEGIN] Applying stored block policies.")]
    private partial void LogApplying();

    [LoggerMessage(Level = LogLevel.Information, Message = "[FW_STARTUP_APPLY_OK] Stored block policies applied.")]
    private partial void LogApplied();

    [LoggerMessage(Level = LogLevel.Error, Message = "[FW_STARTUP_APPLY_FAILED] Stored block policy application failed; the service continues in a degraded state.")]
    private partial void LogFault();
}
