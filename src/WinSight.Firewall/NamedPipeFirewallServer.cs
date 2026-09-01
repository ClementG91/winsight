using System.Diagnostics.CodeAnalysis;
using System.IO.Pipes;
using System.Security.Principal;

namespace WinSight.Firewall;

/// <summary>
/// Hosts the outbound-firewall command endpoint over a hardened local named pipe. Each
/// connection is authenticated while impersonating the client and serves exactly one
/// request/response exchange. The privileged service owns this host; the dashboard is
/// a client and never mutates policy directly.
///
/// The accept loop creates a successor instance before dispatching each connected
/// predecessor. Read-only and privileged callers then enter separate bounded admission
/// lanes, so read-only saturation cannot consume capacity reserved for a machine-policy
/// mutation. WFP transitions remain serialized by the service-side coordinator.
/// </summary>
[SuppressMessage(
    "Design",
    "CA1001:Types that own disposable fields should be disposable",
    Justification = "Admission gates do not allocate wait handles and can outlive the bounded listener drain.")]
public sealed class NamedPipeFirewallServer : IFirewallServiceListener, IFirewallServiceReadiness
{
    private static readonly TimeSpan DefaultRequestReadTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan DefaultResponseWriteTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan DefaultTerminalDrainTimeout = TimeSpan.FromSeconds(2);

    private const int DefaultReadAdmissionCapacity = 4;
    private const int DefaultMutationAdmissionCapacity = 2;
    private const int MaximumPipeInstances = 254;

    private readonly FirewallConnectionHandler _handler;
    private readonly string _pipeName;
    private readonly Func<NamedPipeServerStream, FirewallCallerCapability> _authorise;
    private readonly Func<PipeSecurity> _securityFactory;
    private readonly TimeSpan _requestReadTimeout;
    private readonly TimeSpan _responseWriteTimeout;
    private readonly SemaphoreSlim _readAdmission;
    private readonly SemaphoreSlim _mutationAdmission;
    private readonly SemaphoreSlim _totalAdmission;
    private readonly int _maximumServerInstances;
    private readonly TimeSpan _terminalDrainTimeout;
    private readonly Action? _beforeAdmittedConnectionDispose;
    private readonly TaskCompletionSource _ready =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _connectionFailures;

    /// <param name="handler">The exchange handler wrapping the dispatcher.</param>
    /// <param name="pipeName">Pipe name; defaults to the WinSight firewall pipe.</param>
    /// <param name="authorise">
    /// Authorisation decision for a connected client. Defaults to verifying the
    /// impersonated Windows identity. Tests may inject a deterministic decision.
    /// </param>
    /// <param name="securityFactory">
    /// Produces the pipe ACL for each server instance. Defaults to the hardened ACL.
    /// Tests may inject an ACL scoped to the current user for non-interactive runners.
    /// </param>
    public NamedPipeFirewallServer(
        FirewallConnectionHandler handler,
        string? pipeName = null,
        Func<NamedPipeServerStream, bool>? authorise = null,
        Func<PipeSecurity>? securityFactory = null,
        Func<NamedPipeServerStream, FirewallCallerCapability>? capabilityAuthorise = null,
        TimeSpan? requestReadTimeout = null,
        TimeSpan? responseWriteTimeout = null)
        : this(
            handler,
            pipeName,
            authorise,
            securityFactory,
            capabilityAuthorise,
            requestReadTimeout,
            responseWriteTimeout,
            DefaultReadAdmissionCapacity,
            DefaultMutationAdmissionCapacity,
            terminalDrainTimeout: null,
            beforeAdmittedConnectionDispose: null)
    {
    }

    internal NamedPipeFirewallServer(
        FirewallConnectionHandler handler,
        string? pipeName,
        Func<NamedPipeServerStream, bool>? authorise,
        Func<PipeSecurity>? securityFactory,
        Func<NamedPipeServerStream, FirewallCallerCapability>? capabilityAuthorise,
        TimeSpan? requestReadTimeout,
        TimeSpan? responseWriteTimeout,
        int readAdmissionCapacity,
        int mutationAdmissionCapacity,
        TimeSpan? terminalDrainTimeout = null,
        Action? beforeAdmittedConnectionDispose = null)
    {
        _handler = handler ?? throw new ArgumentNullException(nameof(handler));
        _pipeName = string.IsNullOrWhiteSpace(pipeName) ? FirewallServiceSecurity.DefaultPipeName : pipeName;
        _authorise = capabilityAuthorise ?? (authorise is null
            ? DefaultAuthorise
            : server => authorise(server) ? FirewallCallerCapability.MutateMachinePolicy : FirewallCallerCapability.None);
        _securityFactory = securityFactory ?? FirewallServiceSecurity.CreateHardenedSecurity;
        _requestReadTimeout = ValidateTimeout(requestReadTimeout ?? DefaultRequestReadTimeout);
        _responseWriteTimeout = ValidateTimeout(responseWriteTimeout ?? DefaultResponseWriteTimeout);
        _terminalDrainTimeout = ValidateTimeout(
            terminalDrainTimeout ?? DefaultTerminalDrainTimeout);
        _beforeAdmittedConnectionDispose = beforeAdmittedConnectionDispose;

        _maximumServerInstances = ValidateAdmissionCapacities(
            readAdmissionCapacity,
            mutationAdmissionCapacity);
        _readAdmission = new SemaphoreSlim(readAdmissionCapacity, readAdmissionCapacity);
        _mutationAdmission = new SemaphoreSlim(mutationAdmissionCapacity, mutationAdmissionCapacity);

        // One capacity unit stays free for the connected predecessor while its successor
        // is posted. This is what makes successor-before-dispatch possible without asking
        // Windows for more than read + mutation + one server instances.
        var totalAdmissionCapacity = readAdmissionCapacity + mutationAdmissionCapacity - 1;
        _totalAdmission = new SemaphoreSlim(totalAdmissionCapacity, totalAdmissionCapacity);
    }

    public Task Ready => _ready.Task;

    /// <summary>
    /// Exchanges that failed after the caller was authenticated and admitted. Contained rather
    /// than terminal, and counted so the difference is observable instead of silent.
    /// </summary>
    public int ConnectionFailures => Volatile.Read(ref _connectionFailures);

    /// <summary>
    /// Accepts until cancelled. Startup, successor creation and unexpected connection
    /// processing failures are terminal; expected peer failures are isolated by the
    /// connection handler.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using var runCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var connectionTasks = new List<Task>();
        var activeConnections = new HashSet<NamedPipeServerStream>();
        var activeConnectionsSync = new object();
        var fatalConnectionFailure = new TaskCompletionSource<Exception>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        NamedPipeServerStream? acceptingServer = null;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            acceptingServer = CreateServer(reserveName: true);
            _ready.TrySetResult();

            while (true)
            {
                await ObserveCompletedConnectionsAsync(connectionTasks).ConfigureAwait(false);

                var waitForConnection = acceptingServer.WaitForConnectionAsync(runCancellation.Token);
                var completed = await Task.WhenAny(waitForConnection, fatalConnectionFailure.Task)
                    .ConfigureAwait(false);
                if (completed == fatalConnectionFailure.Task)
                {
                    runCancellation.Cancel();
                    ObserveDetachedCompletion(waitForConnection);
                    throw new InvalidOperationException(
                        "Firewall pipe connection processing failed.",
                        await fatalConnectionFailure.Task.ConfigureAwait(false));
                }

                try
                {
                    await waitForConnection.ConfigureAwait(false);
                }
                catch (IOException)
                {
                    if (fatalConnectionFailure.Task.IsCompleted)
                    {
                        throw new InvalidOperationException(
                            "Firewall pipe connection processing failed.",
                            await fatalConnectionFailure.Task.ConfigureAwait(false));
                    }

                    // A client can connect and close before ConnectNamedPipe's overlapped
                    // completion is observed. Windows reports that peer race as an I/O
                    // failure on this one accept instance. Keep the failed handle alive
                    // until its successor exists so the pipe namespace is never released;
                    // creation/security failures remain terminal.
                    var failedAcceptingServer = acceptingServer;
                    acceptingServer = null;
                    try
                    {
                        acceptingServer = CreateServer(reserveName: false);
                    }
                    catch
                    {
                        CloseServerBestEffort(failedAcceptingServer);
                        throw;
                    }

                    CloseServerBestEffort(failedAcceptingServer);
                    continue;
                }
                var connectedServer = acceptingServer;
                acceptingServer = null;

                try
                {
                    // Keep the namespace owned and an accept instance posted before the
                    // connected predecessor can be dispatched or disposed.
                    acceptingServer = CreateServer(reserveName: false);
                }
                catch
                {
                    CloseServerBestEffort(connectedServer);
                    throw;
                }

                TrackConnection(
                    connectedServer,
                    activeConnections,
                    activeConnectionsSync);
                var connectionTask = ProcessAcceptedConnection(
                    connectedServer,
                    fatalConnectionFailure,
                    activeConnections,
                    activeConnectionsSync,
                    runCancellation.Token);
                connectionTasks.Add(connectionTask);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _ready.TrySetCanceled(cancellationToken);
        }
        catch (Exception ex)
        {
            _ready.TrySetException(ex);
            throw;
        }
        finally
        {
            runCancellation.Cancel();
            if (acceptingServer is not null)
            {
                CloseServerBestEffort(acceptingServer);
            }
            CloseActiveConnections(activeConnections, activeConnectionsSync);
            await DrainConnectionsAsync(connectionTasks, _terminalDrainTimeout)
                .ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Accepts and serves a single connection over a name-reserving instance. This path
    /// deliberately does not require the multi-client accept loop or admission lanes.
    /// </summary>
    public async Task ServeOnceAsync(CancellationToken cancellationToken)
    {
        await using var server = CreateServer(reserveName: true);
        await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var capability = _authorise(server);
            await _handler.HandleAsync(
                server,
                capability,
                _requestReadTimeout,
                _responseWriteTimeout,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            DisconnectExpected(server);
        }
    }

    private Task ProcessAcceptedConnection(
        NamedPipeServerStream server,
        TaskCompletionSource<Exception> fatalConnectionFailure,
        HashSet<NamedPipeServerStream> activeConnections,
        object activeConnectionsSync,
        CancellationToken cancellationToken)
    {
        SemaphoreSlim? lane = null;
        var totalAcquired = false;
        var laneAcquired = false;
        try
        {
            // Authentication and admission intentionally execute before the first await.
            // A rejected peer is closed synchronously, keeping instance count bounded.
            var capability = _authorise(server);

            // A caller with no capability at all is closed here, before any lane is entered.
            // It used to fall into the read lane and travel the whole path - a read of up to five
            // seconds, the dispatch, the write - only to be refused at the end. That is one of the
            // four read slots held for five seconds by a caller who was never going to be answered,
            // and it is available to anyone who can open the pipe. The read/mutate split itself is
            // correct; this is the case that fell through it.
            if (capability == FirewallCallerCapability.None)
            {
                DisposeAcceptedServer(
                    server,
                    fatalConnectionFailure,
                    activeConnections,
                    activeConnectionsSync);
                return Task.CompletedTask;
            }

            lane = capability == FirewallCallerCapability.MutateMachinePolicy
                ? _mutationAdmission
                : _readAdmission;

            totalAcquired = _totalAdmission.Wait(0, CancellationToken.None);
            laneAcquired = totalAcquired && lane.Wait(0, CancellationToken.None);
            if (!laneAcquired)
            {
                DisposeAcceptedServer(
                    server,
                    fatalConnectionFailure,
                    activeConnections,
                    activeConnectionsSync);
                ReleaseAdmissions(lane, laneAcquired, totalAcquired);
                return Task.CompletedTask;
            }

            return ProcessAdmittedConnectionAsync(
                server,
                capability,
                lane,
                fatalConnectionFailure,
                activeConnections,
                activeConnectionsSync,
                cancellationToken);
        }
        catch (Exception ex)
        {
            fatalConnectionFailure.TrySetResult(ex);
            DisposeAcceptedServer(
                server,
                fatalConnectionFailure,
                activeConnections,
                activeConnectionsSync);
            ReleaseAdmissions(lane, laneAcquired, totalAcquired);
            return Task.CompletedTask;
        }
    }

    private async Task ProcessAdmittedConnectionAsync(
        NamedPipeServerStream server,
        FirewallCallerCapability capability,
        SemaphoreSlim lane,
        TaskCompletionSource<Exception> fatalConnectionFailure,
        HashSet<NamedPipeServerStream> activeConnections,
        object activeConnectionsSync,
        CancellationToken cancellationToken)
    {
        try
        {
            await _handler.HandleAsync(
                server,
                capability,
                _requestReadTimeout,
                _responseWriteTimeout,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Listener shutdown cancels in-flight I/O and transitions.
        }
        catch (Exception)
        {
            // Serving one authenticated exchange is not infrastructure. A failure here says the
            // command could not be completed, never that the endpoint is unsound, so it closes
            // this connection and the accept loop keeps running.
            //
            // This used to be terminal, and that made a single unhandled exception anywhere
            // below the dispatcher into a remote stop of the whole service — which, because the
            // WFP session is dynamic, also destroyed every filter BFE held for it. Authentication,
            // server creation and admission failures remain terminal below and above this method:
            // those genuinely are the endpoint's own machinery, and failing closed is right there.
            Interlocked.Increment(ref _connectionFailures);
        }
        finally
        {
            try
            {
                _beforeAdmittedConnectionDispose?.Invoke();
            }
            catch (Exception ex)
            {
                fatalConnectionFailure.TrySetResult(ex);
            }
            finally
            {
                DisposeAcceptedServer(
                    server,
                    fatalConnectionFailure,
                    activeConnections,
                    activeConnectionsSync);
                ReleaseAdmissions(lane, laneAcquired: true, totalAcquired: true);
            }
        }
    }

    private NamedPipeServerStream CreateServer(bool reserveName)
    {
        var security = _securityFactory();
        var options = PipeOptions.Asynchronous;
        if (reserveName)
        {
            options |= PipeOptions.FirstPipeInstance;
        }

        return NamedPipeServerStreamAcl.Create(
            _pipeName,
            PipeDirection.InOut,
            _maximumServerInstances,
            PipeTransmissionMode.Byte,
            options,
            inBufferSize: 0,
            outBufferSize: 0,
            security);
    }

    private static async Task ObserveCompletedConnectionsAsync(List<Task> connectionTasks)
    {
        for (var index = connectionTasks.Count - 1; index >= 0; index--)
        {
            if (!connectionTasks[index].IsCompleted)
            {
                continue;
            }

            await connectionTasks[index].ConfigureAwait(false);
            connectionTasks.RemoveAt(index);
        }
    }

    private static void DisposeAcceptedServer(
        NamedPipeServerStream server,
        TaskCompletionSource<Exception> fatalConnectionFailure,
        HashSet<NamedPipeServerStream> activeConnections,
        object activeConnectionsSync)
    {
        DisconnectExpected(server);
        try
        {
            server.Dispose();
        }
        catch (Exception ex)
        {
            fatalConnectionFailure.TrySetResult(ex);
        }
        finally
        {
            lock (activeConnectionsSync)
            {
                activeConnections.Remove(server);
            }
        }
    }

    private void ReleaseAdmissions(
        SemaphoreSlim? lane,
        bool laneAcquired,
        bool totalAcquired)
    {
        if (laneAcquired)
        {
            lane!.Release();
        }
        if (totalAcquired)
        {
            _totalAdmission.Release();
        }
    }

    private static void TrackConnection(
        NamedPipeServerStream server,
        HashSet<NamedPipeServerStream> activeConnections,
        object activeConnectionsSync)
    {
        lock (activeConnectionsSync)
        {
            activeConnections.Add(server);
        }
    }

    private static void CloseActiveConnections(
        HashSet<NamedPipeServerStream> activeConnections,
        object activeConnectionsSync)
    {
        NamedPipeServerStream[] snapshot;
        lock (activeConnectionsSync)
        {
            snapshot = [.. activeConnections];
        }

        foreach (var server in snapshot)
        {
            CloseServerBestEffort(server);
        }
    }

    private static void CloseServerBestEffort(NamedPipeServerStream server)
    {
        DisconnectExpected(server);
        try
        {
            server.Dispose();
        }
        catch (Exception)
        {
            // Terminal cleanup must continue closing the remaining owned handles.
        }
    }

    private static async Task DrainConnectionsAsync(
        List<Task> connectionTasks,
        TimeSpan terminalDrainTimeout)
    {
        var allConnections = Task.WhenAll(connectionTasks);
        if (!allConnections.IsCompleted)
        {
            var completed = await Task.WhenAny(
                allConnections,
                Task.Delay(terminalDrainTimeout, CancellationToken.None)).ConfigureAwait(false);
            if (completed != allConnections)
            {
                ObserveDetachedCompletion(allConnections);
                return;
            }
        }

        await ObserveWithoutThrowAsync(allConnections).ConfigureAwait(false);
    }

    private static async Task ObserveWithoutThrowAsync(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (Exception)
        {
            // The primary listener failure is already classified and must reach the host.
        }
    }

    private static void ObserveDetachedCompletion(Task task)
    {
        _ = task.ContinueWith(
            static completed => _ = completed.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private static void DisconnectExpected(NamedPipeServerStream server)
    {
        try
        {
            if (server.IsConnected)
            {
                server.Disconnect();
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or ObjectDisposedException)
        {
            // A peer can vanish between IsConnected and Disconnect.
        }
    }

    private static int ValidateAdmissionCapacities(
        int readAdmissionCapacity,
        int mutationAdmissionCapacity)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(readAdmissionCapacity, 1);
        // The combined handoff limit is one below the sum of both lanes. Requiring two
        // mutation permits still leaves one mutation admission when all read permits
        // are occupied.
        ArgumentOutOfRangeException.ThrowIfLessThan(mutationAdmissionCapacity, 2);

        var maximumServerInstances =
            (long)readAdmissionCapacity + mutationAdmissionCapacity + 1;
        return maximumServerInstances <= MaximumPipeInstances
            ? (int)maximumServerInstances
            : throw new ArgumentOutOfRangeException(nameof(mutationAdmissionCapacity));
    }

    private static TimeSpan ValidateTimeout(TimeSpan timeout) =>
        timeout > TimeSpan.Zero && timeout <= TimeSpan.FromMinutes(1)
            ? timeout
            : throw new ArgumentOutOfRangeException(nameof(timeout));

    private static FirewallCallerCapability DefaultAuthorise(NamedPipeServerStream server)
    {
        try
        {
            var capability = FirewallCallerCapability.None;
            server.RunAsClient(() =>
            {
                using var identity = WindowsIdentity.GetCurrent();
                capability = FirewallServiceSecurity.GetCallerCapability(identity);
            });
            return capability;
        }
        catch (Exception)
        {
            // Fail closed: if the client identity cannot be established, deny.
            //
            // Every exception, not a list of three. The list said "fail closed" and did not do it:
            // WindowsPrincipal.IsInRole(SecurityIdentifier) raises SecurityException when
            // CheckTokenMembership fails, and reading identity.Groups raises Win32Exception - neither
            // was caught, so either one escaped into ProcessAcceptedConnection, which classifies any
            // throw there as a fatal connection failure. The accept loop then stops the host, and
            // because the WFP session is dynamic, BFE destroys every filter the service owned.
            //
            // This is the same defect FirewallRequestDispatcher was hardened against one layer down,
            // where a long comment describes exactly this failure. Authorisation sits above that
            // hardening and kept its narrow list. Denying is the only correct answer here whatever
            // went wrong, so there is nothing an enumeration of types can buy.
            return FirewallCallerCapability.None;
        }
    }
}
