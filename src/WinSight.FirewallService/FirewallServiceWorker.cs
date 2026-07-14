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

    public FirewallServiceWorker(IFirewallServiceListener listener, ILogger<FirewallServiceWorker> logger)
    {
        _listener = listener ?? throw new ArgumentNullException(nameof(listener));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
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
        catch (Exception ex)
        {
            LogListenerFault(ex);
            throw;
        }
        finally
        {
            LogStopped();
        }
    }

    [LoggerMessage(Level = LogLevel.Information,
        Message = "WinSight firewall service listening (audit-only, no WFP mutation).")]
    private partial void LogListening();

    [LoggerMessage(Level = LogLevel.Error, Message = "The firewall listener stopped unexpectedly.")]
    private partial void LogListenerFault(Exception exception);

    [LoggerMessage(Level = LogLevel.Information, Message = "WinSight firewall service stopped.")]
    private partial void LogStopped();
}
