using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WinSight.Firewall;

namespace WinSight.FirewallService;

/// <summary>
/// Final containment boundary for an endpoint loss. Graceful host shutdown gets a fixed
/// window; privileged work that ignores cancellation cannot survive the service process.
/// </summary>
internal interface IFirewallEndpointLossWatchdog
{
    void Arm();
}

internal sealed class NoOpFirewallEndpointLossWatchdog : IFirewallEndpointLossWatchdog
{
    internal static NoOpFirewallEndpointLossWatchdog Instance { get; } = new();

    private NoOpFirewallEndpointLossWatchdog()
    {
    }

    public void Arm()
    {
    }
}

internal sealed class HardExitFirewallEndpointLossWatchdog : IFirewallEndpointLossWatchdog
{
    internal static readonly TimeSpan ProductionHardExitDelay = TimeSpan.FromSeconds(8);
    internal const string ExpiredCode = "[FW_PIPE_WATCHDOG_EXPIRED]";
    internal const string StartFailureCode = "[FW_PIPE_WATCHDOG_START_FAILED]";
    internal static Action<string> ProductionTermination { get; } = Environment.FailFast;

    private readonly TimeSpan _hardExitDelay;
    private readonly Action<string> _terminateImmediately;
    private int _armed;

    internal HardExitFirewallEndpointLossWatchdog()
        : this(
            ProductionHardExitDelay,
            ProductionTermination)
    {
    }

    internal HardExitFirewallEndpointLossWatchdog(
        TimeSpan hardExitDelay,
        Action<string> terminateImmediately)
    {
        if (hardExitDelay <= TimeSpan.Zero || hardExitDelay > ProductionHardExitDelay)
        {
            throw new ArgumentOutOfRangeException(nameof(hardExitDelay));
        }

        _hardExitDelay = hardExitDelay;
        _terminateImmediately = terminateImmediately
            ?? throw new ArgumentNullException(nameof(terminateImmediately));
    }

    internal TimeSpan HardExitDelay => _hardExitDelay;

    internal Action<string> TerminateImmediately => _terminateImmediately;

    public void Arm()
    {
        if (Interlocked.Exchange(ref _armed, 1) != 0)
        {
            return;
        }

        try
        {
            var watchdog = new Thread(() =>
            {
                Thread.Sleep(_hardExitDelay);
                _terminateImmediately(ExpiredCode);
            })
            {
                IsBackground = true,
                Name = "WinSight-Firewall-Endpoint-Watchdog",
            };
            watchdog.Start();
        }
        catch (Exception)
        {
            _terminateImmediately(StartFailureCode);
        }
    }
}

internal static class FirewallServiceWorkerComposition
{
    internal static IServiceCollection AddFirewallServiceWorker(
        this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton<IFirewallEndpointLossWatchdog>(
            static _ => new HardExitFirewallEndpointLossWatchdog());
        services.AddSingleton<FirewallServiceExitSignal>();
        services.AddHostedService(sp => new FirewallServiceWorker(
            sp.GetRequiredService<IFirewallServiceListener>(),
            sp.GetRequiredService<ILogger<FirewallServiceWorker>>(),
            sp.GetRequiredService<IHostApplicationLifetime>(),
            sp.GetRequiredService<IFirewallEndpointLossWatchdog>(),
            sp.GetRequiredService<FirewallServiceExitSignal>()));
        return services;
    }
}
