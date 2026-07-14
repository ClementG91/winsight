using System.ComponentModel;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WinSight.FirewallService;

/// <summary>
/// At service start, re-applies the stored Block policies to WFP. WinSight's WFP filters
/// are non-persistent (removed on reboot), so the service reinstalls them on every boot
/// when enforcement is enabled. This runs only when the host was built in enforcement mode;
/// in audit-only mode the service does not register it. A failure is logged and never
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
            LogFault(ex);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    [LoggerMessage(Level = LogLevel.Information, Message = "Enforcement enabled: applying stored block policies.")]
    private partial void LogApplying();

    [LoggerMessage(Level = LogLevel.Information, Message = "Stored block policies applied.")]
    private partial void LogApplied();

    [LoggerMessage(Level = LogLevel.Error, Message = "Applying stored block policies failed; the service continues.")]
    private partial void LogFault(Exception exception);
}
