using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WinSight.Firewall;

namespace WinSight.FirewallService;

/// <summary>
/// Hosts the firewall command listener for the lifetime of the Windows service. It runs
/// the listener until the host requests shutdown; a listener fault is logged and stops
/// the service host. A bounded hard-exit watchdog contains privileged work that ignores
/// cancellation. Explicit WFP transitions are handled behind the listener by the
/// service-side coordinator.
///
/// The invariant this type enforces: the service never outlives its endpoint. Any exit
/// from the listener that shutdown did not ask for - a fault, a silent completion, or a
/// return before readiness - stops the host. Returning quietly would leave the service
/// reporting Running to the SCM with nothing accepting connections, so every caller would
/// see a timeout while the machine looked healthy.
/// </summary>
public sealed partial class FirewallServiceWorker : BackgroundService
{
    private readonly IFirewallServiceListener _listener;
    private readonly ILogger<FirewallServiceWorker> _logger;
    private readonly IHostApplicationLifetime? _applicationLifetime;
    private readonly IFirewallEndpointLossWatchdog _endpointLossWatchdog;
    private readonly FirewallServiceExitSignal? _exitSignal;

    public FirewallServiceWorker(
        IFirewallServiceListener listener,
        ILogger<FirewallServiceWorker> logger,
        IHostApplicationLifetime? applicationLifetime = null)
        : this(
            listener,
            logger,
            applicationLifetime,
            NoOpFirewallEndpointLossWatchdog.Instance)
    {
    }

    internal FirewallServiceWorker(
        IFirewallServiceListener listener,
        ILogger<FirewallServiceWorker> logger,
        IHostApplicationLifetime? applicationLifetime,
        IFirewallEndpointLossWatchdog endpointLossWatchdog,
        FirewallServiceExitSignal? exitSignal = null)
    {
        _exitSignal = exitSignal;
        _listener = listener ?? throw new ArgumentNullException(nameof(listener));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _applicationLifetime = applicationLifetime;
        _endpointLossWatchdog = endpointLossWatchdog
            ?? throw new ArgumentNullException(nameof(endpointLossWatchdog));
    }

    internal IFirewallEndpointLossWatchdog EndpointLossWatchdog => _endpointLossWatchdog;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var endpointLost = false;
        var listenerInvoked = false;
        var listenerFailure = ListenerFailureKind.ListenerCompleted;
        try
        {
            listenerInvoked = true;
            var listenerTask = _listener.RunAsync(stoppingToken);
            if (_listener is IFirewallServiceReadiness readiness)
            {
                var readyTask = readiness.Ready;
                _ = await Task.WhenAny(listenerTask, readyTask)
                    .ConfigureAwait(false);
                if (listenerTask.IsCompleted)
                {
                    // Finished before it ever announced readiness. Awaiting rethrows a
                    // fault; a quiet completion here means the endpoint never came up.
                    await listenerTask.ConfigureAwait(false);
                    endpointLost = !stoppingToken.IsCancellationRequested;
                    return;
                }

                // Readiness is an owned lifecycle signal, not merely a race marker. A
                // faulted or cancelled readiness task must never produce LISTENING.
                await readyTask.ConfigureAwait(false);
                if (listenerTask.IsCompleted)
                {
                    await listenerTask.ConfigureAwait(false);
                    endpointLost = !stoppingToken.IsCancellationRequested;
                    return;
                }
            }

            LogListening();
            await listenerTask.ConfigureAwait(false);

            // The accept loop returned on its own. Outside shutdown the pipe is gone
            // while the service would otherwise stay Running.
            endpointLost = !stoppingToken.IsCancellationRequested;
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal shutdown.
        }
        catch (Exception ex)
        {
            listenerFailure = ClassifyListenerFailure(ex);
            endpointLost = !stoppingToken.IsCancellationRequested;
        }
        finally
        {
            // Once ExecuteAsync leaves, the listener endpoint is no longer owned by this
            // worker. Arm even during requested shutdown so stuck privileged teardown is
            // bounded; a normal process exit removes the background watchdog silently.
            if (listenerInvoked)
            {
                _endpointLossWatchdog.Arm();
            }

            if (endpointLost)
            {
                // Recorded before the host is asked to stop, so the process exits non-zero. A clean
                // exit tells the SCM the stop was intentional and its restart actions never run -
                // which is why an endpoint that was squatted or faulted stayed down until somebody
                // noticed.
                _exitSignal?.ReportEndpointLost();
                StopApplicationBestEffort();
                LogListenerFaultBestEffort(listenerFailure);
            }

            LogStoppedBestEffort();
        }
    }

    private void StopApplicationBestEffort()
    {
        try
        {
            _applicationLifetime?.StopApplication();
        }
        catch (Exception)
        {
            // The already-armed watchdog remains the terminal containment boundary.
        }
    }

    private static ListenerFailureKind ClassifyListenerFailure(Exception exception) =>
        exception.GetBaseException() switch
        {
            ObjectDisposedException => ListenerFailureKind.ObjectDisposed,
            UnauthorizedAccessException or System.Security.SecurityException => ListenerFailureKind.Unauthorized,
            System.ComponentModel.Win32Exception => ListenerFailureKind.Native,
            IOException => ListenerFailureKind.Io,
            InvalidOperationException => ListenerFailureKind.InvalidOperation,
            ArgumentException => ListenerFailureKind.Configuration,
            _ => ListenerFailureKind.Unexpected,
        };

    private void LogListenerFaultBestEffort(ListenerFailureKind failureKind)
    {
        try
        {
            switch (failureKind)
            {
                case ListenerFailureKind.ListenerCompleted:
                    LogListenerCompleted();
                    break;
                case ListenerFailureKind.Native:
                    LogListenerNativeFailure();
                    break;
                case ListenerFailureKind.Io:
                    LogListenerIoFailure();
                    break;
                case ListenerFailureKind.InvalidOperation:
                    LogListenerInvalidOperationFailure();
                    break;
                case ListenerFailureKind.ObjectDisposed:
                    LogListenerObjectDisposedFailure();
                    break;
                case ListenerFailureKind.Unauthorized:
                    LogListenerUnauthorizedFailure();
                    break;
                case ListenerFailureKind.Configuration:
                    LogListenerConfigurationFailure();
                    break;
                default:
                    LogListenerUnexpectedFailure();
                    break;
            }
        }
        catch (Exception)
        {
            // Diagnostics must not suppress containment or graceful host shutdown.
        }
    }

    private void LogStoppedBestEffort()
    {
        try
        {
            LogStopped();
        }
        catch (Exception)
        {
            // Shutdown diagnostics are best-effort.
        }
    }

    [LoggerMessage(Level = LogLevel.Information,
        Message = "[FW_PIPE_LISTENING] WinSight firewall service listening.")]
    private partial void LogListening();

    [LoggerMessage(Level = LogLevel.Error,
        Message = "[FW_PIPE_LISTENER_FAILED] The firewall listener stopped unexpectedly. Failure=ListenerCompleted.")]
    private partial void LogListenerCompleted();

    [LoggerMessage(Level = LogLevel.Error,
        Message = "[FW_PIPE_LISTENER_FAILED] The firewall listener stopped unexpectedly. Failure=Native.")]
    private partial void LogListenerNativeFailure();

    [LoggerMessage(Level = LogLevel.Error,
        Message = "[FW_PIPE_LISTENER_FAILED] The firewall listener stopped unexpectedly. Failure=IO.")]
    private partial void LogListenerIoFailure();

    [LoggerMessage(Level = LogLevel.Error,
        Message = "[FW_PIPE_LISTENER_FAILED] The firewall listener stopped unexpectedly. Failure=InvalidOperation.")]
    private partial void LogListenerInvalidOperationFailure();

    [LoggerMessage(Level = LogLevel.Error,
        Message = "[FW_PIPE_LISTENER_FAILED] The firewall listener stopped unexpectedly. Failure=ObjectDisposed.")]
    private partial void LogListenerObjectDisposedFailure();

    [LoggerMessage(Level = LogLevel.Error,
        Message = "[FW_PIPE_LISTENER_FAILED] The firewall listener stopped unexpectedly. Failure=Unauthorized.")]
    private partial void LogListenerUnauthorizedFailure();

    [LoggerMessage(Level = LogLevel.Error,
        Message = "[FW_PIPE_LISTENER_FAILED] The firewall listener stopped unexpectedly. Failure=Configuration.")]
    private partial void LogListenerConfigurationFailure();

    [LoggerMessage(Level = LogLevel.Error,
        Message = "[FW_PIPE_LISTENER_FAILED] The firewall listener stopped unexpectedly. Failure=Unexpected.")]
    private partial void LogListenerUnexpectedFailure();

    [LoggerMessage(Level = LogLevel.Information, Message = "[FW_SERVICE_STOPPED] WinSight firewall service stopped.")]
    private partial void LogStopped();

    private enum ListenerFailureKind
    {
        ListenerCompleted,
        Native,
        Io,
        InvalidOperation,
        ObjectDisposed,
        Unauthorized,
        Configuration,
        Unexpected,
    }
}
