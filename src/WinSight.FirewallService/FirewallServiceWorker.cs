using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WinSight.Firewall;

namespace WinSight.FirewallService;

/// <summary>
/// Hosts the firewall command listener for the lifetime of the Windows service. It runs
/// the listener until the host requests shutdown; a listener fault is logged and stops
/// the service cleanly rather than crashing it. This worker performs no WFP mutation:
/// the shipped service is audit-only.
/// </summary>
public sealed partial class FirewallServiceWorker : BackgroundService
{
    private readonly IFirewallServiceListener _listener;
    private readonly ILogger<FirewallServiceWorker> _logger;
    private readonly IHostApplicationLifetime? _applicationLifetime;

    public FirewallServiceWorker(
        IFirewallServiceListener listener,
        ILogger<FirewallServiceWorker> logger,
        IHostApplicationLifetime? applicationLifetime = null)
    {
        _listener = listener ?? throw new ArgumentNullException(nameof(listener));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _applicationLifetime = applicationLifetime;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        LogListening();
        try
        {
            await _listener.RunAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal shutdown.
        }
        catch (Exception)
        {
            LogListenerFault();
            _applicationLifetime?.StopApplication();
        }
        finally
        {
            LogStopped();
        }
    }

    [LoggerMessage(Level = LogLevel.Information,
        Message = "[FW_PIPE_LISTENING] WinSight firewall service listening.")]
    private partial void LogListening();

    [LoggerMessage(Level = LogLevel.Error, Message = "[FW_PIPE_LISTENER_FAILED] The firewall listener stopped unexpectedly.")]
    private partial void LogListenerFault();

    [LoggerMessage(Level = LogLevel.Information, Message = "[FW_SERVICE_STOPPED] WinSight firewall service stopped.")]
    private partial void LogStopped();
}
