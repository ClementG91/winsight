using System.ComponentModel;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WinSight.Firewall;
using WinSight.NetMonitor;

namespace WinSight.FirewallService;

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
/// It never crashes the service. The trace session is privileged, and the kernel logger it needs is
/// a single machine-wide session another tool may already hold; the pipe endpoint matters more than
/// this feature, so a failure is logged once and the observer stands down, leaving the rest of the
/// service running.
///
/// Two connections it cannot see, stated plainly because a security tool that hides its blind spots
/// is worse than one without the feature: one made by a process that started before the session and
/// never announced its command line, and, once the log is full, apps beyond the cap. Both are
/// counted rather than dropped in silence.
/// </remarks>
public sealed partial class OutboundObserverService : BackgroundService
{
    /// <summary>How long a policy snapshot is reused before the store is read again.</summary>
    private static readonly TimeSpan PolicyRefreshInterval = TimeSpan.FromSeconds(5);

    private readonly OutboundConnectionWatcher _watcher;
    private readonly FirewallPolicyStore _store;
    private readonly PendingOutboundLog _log;
    private readonly ILogger<OutboundObserverService> _logger;
    private readonly TimeProvider _time;

    private HashSet<string> _ruled = new(StringComparer.OrdinalIgnoreCase);
    // Ticks rather than a DateTimeOffset, because two threads write it: the trace thread claims a
    // window before queueing a reload, and the reload itself stamps the load it just completed. A
    // 64-bit field is written atomically, so the worst a race costs is one extra refresh.
    private long _ruledLoadedTicks = DateTimeOffset.MinValue.UtcTicks;
    // 1 while a reload is in flight, so a burst of connections starts one refresh and not one each.
    private int _refreshing;
    // The reload in flight. Tracked rather than fired and forgotten: a background file read must not
    // outlive the service that started it, or shutdown races its own store.
    private Task _refresh = Task.CompletedTask;
    private int _unattributed;

    public OutboundObserverService(
        OutboundConnectionWatcher watcher,
        FirewallPolicyStore store,
        PendingOutboundLog log,
        ILogger<OutboundObserverService> logger,
        TimeProvider? time = null)
    {
        _watcher = watcher ?? throw new ArgumentNullException(nameof(watcher));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _time = time ?? TimeProvider.System;
    }

    /// <summary>Connections that carried no identity a policy could be keyed on.</summary>
    public int UnattributedConnections => Volatile.Read(ref _unattributed);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Prime the snapshot before any connection can be judged against it. This is the one place a
        // policy read is free: the host's start path, asynchronously, with no trace callback waiting.
        // Without it the first connections would be measured against an empty set and an app the
        // operator had already ruled on would be logged as pending once per service start.
        await RefreshRuledAsync().ConfigureAwait(false);

        // The ETW pump blocks its thread until the session stops, so it cannot run on the host's
        // startup path without holding the whole service back.
        await Task.Factory.StartNew(
            () => Pump(stoppingToken),
            stoppingToken,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default).ConfigureAwait(false);
    }

    private void Pump(CancellationToken stoppingToken)
    {
        try
        {
            LogWatching();
            _watcher.Watch(OnConnection, OnUnattributedConnection, stoppingToken);
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

        // The connection arrives already attributed: the watcher captured the executable when the
        // kernel announced the process, while it was still alive.
        var path = connection.ExecutablePath;

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

    /// <summary>
    /// Called for an outbound connection whose process could not be named well enough to rule on.
    /// </summary>
    /// <remarks>
    /// These used to be discarded inside the watcher, which meant <see cref="UnattributedConnections"/>
    /// stood at zero on a machine that was losing connections — a health counter that structurally
    /// could not count the failure it is named for. Measured against a live kernel session, this
    /// population is the bare-name launches (<c>powershell.exe</c>, <c>cmd</c>, <c>node</c>), which
    /// is precisely the traffic an operator would want to know went unseen.
    ///
    /// It deliberately does not reach the pending log. That log is the list of apps the operator can
    /// Allow or Block, and a rule keyed on a bare name would apply to every program sharing it.
    /// Counting is the honest answer: the connection is known to have happened and known not to be
    /// rulable.
    /// </remarks>
    public void OnUnattributedConnection(int processId, string? imageName)
    {
        Interlocked.Increment(ref _unattributed);
        LogUnattributed(processId, imageName ?? "unknown");
    }

    /// <summary>
    /// The applications the operator has already ruled on. Returns immediately, always.
    /// </summary>
    /// <remarks>
    /// <b>This must never touch the disk.</b> It is called from the ETW trace callback for every
    /// outbound connection, and a real-time ETW session drops events when its consumer is slow — so
    /// blocking here to read the policy file risks losing the very connections this service exists
    /// to observe. It previously did exactly that, once every refresh interval, via
    /// <c>LoadOrAuditAsync().GetAwaiter().GetResult()</c>: synchronous file I/O on the trace thread,
    /// which the project's own standards forbid and which the surrounding comments already claimed
    /// was not happening.
    ///
    /// A stale window is the price, and it is the right one: this decides whether an app the operator
    /// already ruled on is worth logging as pending. Being a few seconds late there is noise in a
    /// notification list, never a missed block — enforcement is WFP's job and does not consult this.
    /// </remarks>
    private HashSet<string> Ruled()
    {
        var now = _time.GetUtcNow();
        var loadedUtc = new DateTimeOffset(Volatile.Read(ref _ruledLoadedTicks), TimeSpan.Zero);
        if (now - loadedUtc >= PolicyRefreshInterval
            && Interlocked.CompareExchange(ref _refreshing, 1, 0) == 0)
        {
            // Claim the window here, on this thread, before the load is queued: a burst of
            // connections must start one refresh, not one per event.
            Volatile.Write(ref _ruledLoadedTicks, now.UtcTicks);
            Volatile.Write(ref _refresh, RefreshInBackgroundAsync());
        }

        return Volatile.Read(ref _ruled);
    }

    /// <summary>The reload in flight, so shutdown and tests can wait for it rather than race it.</summary>
    internal Task PendingRefresh => Volatile.Read(ref _refresh);

    /// <summary>
    /// Waits for a policy reload still in flight before the service counts as stopped.
    /// </summary>
    /// <remarks>
    /// Without this the refresh is fire-and-forget: a file read started by the last observed
    /// connection can still be running while the host tears the service down, which is how a clean
    /// shutdown turns into an I/O error on a thread nobody is watching.
    /// </remarks>
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
        await PendingRefresh.ConfigureAwait(false);
    }

    private async Task RefreshInBackgroundAsync()
    {
        try
        {
            // Task.Run, not a bare call: the point is that the load runs on a pool thread and the
            // trace callback returns now. A short file read is exactly what the pool is for — unlike
            // the pump above, which blocks until shutdown and therefore owns a thread of its own.
            await Task.Run(RefreshRuledAsync).ConfigureAwait(false);
        }
        finally
        {
            Volatile.Write(ref _refreshing, 0);
        }
    }

    /// <summary>
    /// Reloads the ruled-application snapshot from the store.
    /// </summary>
    /// <remarks>
    /// Internal and awaitable on purpose: the service awaits it once at startup, the background
    /// refresh awaits it on a pool thread, and tests await it to stay deterministic. Nothing calls it
    /// from the trace thread, which is the reason it exists separately from <see cref="Ruled"/>.
    /// </remarks>
    internal async Task RefreshRuledAsync()
    {
        try
        {
            var load = await _store.LoadOrAuditAsync().ConfigureAwait(false);
            var ruled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var policy in load.Configuration.Policies)
            {
                ruled.Add(policy.ExecutablePath);
            }
            Volatile.Write(ref _ruled, ruled);
            // Stamp the load that just succeeded. Without this the startup prime left the snapshot
            // looking never-loaded, so the very first connection after start would queue a second,
            // redundant read of a file that had just been read — and in tests that stray background
            // read outlived the test that caused it and held the store open.
            Volatile.Write(ref _ruledLoadedTicks, _time.GetUtcNow().UtcTicks);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            // Keep the previous snapshot: reporting an already-ruled app is noise, not a hazard.
            // The stamp is deliberately not advanced here. On the refresh path that costs nothing —
            // Ruled() already claimed the window before queueing, so a failed load waits out the
            // interval like any other and cannot become a retry storm on a corrupt store. On the
            // startup prime, which has no claim, it is what makes the first connection try again.
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "[FW_OBSERVER_WATCHING] Watching outbound connections for applications with no policy.")]
    private partial void LogWatching();

    [LoggerMessage(Level = LogLevel.Information, Message = "[FW_OBSERVER_FIRST_SEEN] An application with no policy reached the network.")]
    private partial void LogFirstSeen();

    [LoggerMessage(Level = LogLevel.Warning, Message = "[FW_OBSERVER_UNAVAILABLE] Outbound observation is unavailable; the firewall service continues without it.")]
    private partial void LogUnavailable();

    // The image name, never a path: this branch is reached precisely because there is no path, and
    // a bare name is not sensitive the way a user's directory layout is.
    [LoggerMessage(Level = LogLevel.Information, Message = "[FW_OBSERVER_UNATTRIBUTED] A connection from pid {ProcessId} ({ImageName}) could not be attributed to a rulable executable.")]
    private partial void LogUnattributed(int processId, string imageName);
}
