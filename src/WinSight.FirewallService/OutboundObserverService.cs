using System.ComponentModel;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WinSight.Firewall;
using WinSight.NetMonitor;

namespace WinSight.FirewallService;

/// <summary>
/// Resolves the process behind an outbound connection. Separated so the observer can be tested
/// without ETW and without spawning processes.
/// </summary>
public interface IProcessImageResolver
{
    /// <summary>
    /// The full executable path of <paramref name="processId"/>, or null when it cannot be
    /// attributed — the process already exited, or it is protected and refuses the query.
    /// </summary>
    string? Resolve(int processId);
}

/// <summary>
/// Resolves a process id to its executable, deliberately without a cache.
/// </summary>
/// <remarks>
/// Caching by process id looks free and is not: Windows reuses process ids, so a cached entry
/// eventually names a different program than the one that connected. Every policy here is keyed on
/// the executable, so a stale hit would let the operator rule on, or be alarmed by, the wrong
/// application. Paying for a fresh lookup per connection is the cheaper mistake.
/// </remarks>
public sealed class ProcessImageResolver : IProcessImageResolver
{
    public string? Resolve(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return process.MainModule?.FileName;
        }
        catch (Exception ex) when (ex is ArgumentException or Win32Exception
                                     or NotSupportedException or InvalidOperationException)
        {
            // Exited between connecting and being asked about, or protected and refusing the
            // query. Either way there is no honest attribution to make.
            return null;
        }
    }
}

/// <summary>
/// Watches outbound connections and records the applications the operator has never ruled on, so
/// the dashboard can say "this just talked to the internet, allow or block it?".
/// </summary>
/// <remarks>
/// Reporting only. Without a callout driver a user-mode WFP filter cannot hold a connection while
/// the operator decides, so the connection that triggers a notice has already completed and the
/// decision governs the next one. The alternative — flipping WFP to default-block — needs explicit
/// permits for DNS, DHCP and system services and takes the machine offline when it is wrong.
///
/// It never crashes the service. The ETW session is privileged and can be refused or lost, and the
/// pipe endpoint matters more than this feature: a failure is logged once and the observer stops,
/// leaving the rest of the service running rather than taking it down.
///
/// Two connections it cannot see, stated plainly because a security tool that hides its blind spots
/// is worse than one without the feature: a process that exits before it can be resolved, and, once
/// the log is full, apps beyond the cap. Both are counted rather than dropped in silence.
/// </remarks>
public sealed partial class OutboundObserverService : BackgroundService
{
    /// <summary>How long a policy snapshot is reused before the store is read again.</summary>
    private static readonly TimeSpan PolicyRefreshInterval = TimeSpan.FromSeconds(5);

    private readonly OutboundConnectionWatcher _watcher;
    private readonly IProcessImageResolver _resolver;
    private readonly FirewallPolicyStore _store;
    private readonly PendingOutboundLog _log;
    private readonly ILogger<OutboundObserverService> _logger;
    private readonly TimeProvider _time;

    private HashSet<string> _ruled = new(StringComparer.OrdinalIgnoreCase);
    private DateTimeOffset _ruledLoadedUtc = DateTimeOffset.MinValue;
    private int _unattributed;

    public OutboundObserverService(
        OutboundConnectionWatcher watcher,
        IProcessImageResolver resolver,
        FirewallPolicyStore store,
        PendingOutboundLog log,
        ILogger<OutboundObserverService> logger,
        TimeProvider? time = null)
    {
        _watcher = watcher ?? throw new ArgumentNullException(nameof(watcher));
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _time = time ?? TimeProvider.System;
    }

    /// <summary>Connections that could not be attributed to an executable.</summary>
    public int UnattributedConnections => Volatile.Read(ref _unattributed);

    protected override Task ExecuteAsync(CancellationToken stoppingToken) =>
        // The ETW pump blocks its thread until the session stops, so it cannot run on the host's
        // startup path without holding the whole service back.
        Task.Factory.StartNew(
            () => Pump(stoppingToken),
            stoppingToken,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);

    private void Pump(CancellationToken stoppingToken)
    {
        try
        {
            LogWatching();
            _watcher.Watch(OnConnection, stoppingToken);
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or Win32Exception or InvalidOperationException)
        {
            // The pipe endpoint is worth more than this feature: report and stand down.
            LogUnavailable();
        }
    }

    /// <summary>
    /// Called on the ETW trace thread for every outbound connection attempt. Public because it is
    /// the unit of behaviour worth testing, and testing it through a live ETW session would prove
    /// nothing about the attribution and filtering that actually matter here.
    /// </summary>
    public void OnConnection(OutboundConnectionEvent connection)
    {
        ArgumentNullException.ThrowIfNull(connection);

        var path = _resolver.Resolve(connection.ProcessId);
        if (string.IsNullOrWhiteSpace(path))
        {
            Interlocked.Increment(ref _unattributed);
            return;
        }

        // An app the operator already ruled on is not news, and letting it into the log would let
        // routine traffic fill the cap and push genuinely unknown apps out.
        if (Ruled().Contains(path))
        {
            return;
        }

        try
        {
            if (_log.Observe(path, connection.Remote, _time.GetUtcNow()))
            {
                LogFirstSeen();
            }
        }
        catch (ArgumentException)
        {
            // No absolute path means no identity a policy could be keyed on.
            Interlocked.Increment(ref _unattributed);
        }
    }

    private HashSet<string> Ruled()
    {
        var now = _time.GetUtcNow();
        if (now - _ruledLoadedUtc < PolicyRefreshInterval)
        {
            return _ruled;
        }

        try
        {
            var load = _store.LoadOrAuditAsync().GetAwaiter().GetResult();
            var ruled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var policy in load.Configuration.Policies)
            {
                ruled.Add(policy.ExecutablePath);
            }
            _ruled = ruled;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            // Keep the previous snapshot: reporting an already-ruled app is noise, not a hazard.
        }
        _ruledLoadedUtc = now;
        return _ruled;
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "[FW_OBSERVER_WATCHING] Watching outbound connections for applications with no policy.")]
    private partial void LogWatching();

    [LoggerMessage(Level = LogLevel.Information, Message = "[FW_OBSERVER_FIRST_SEEN] An application with no policy reached the network.")]
    private partial void LogFirstSeen();

    [LoggerMessage(Level = LogLevel.Warning, Message = "[FW_OBSERVER_UNAVAILABLE] Outbound observation is unavailable; the firewall service continues without it.")]
    private partial void LogUnavailable();
}
