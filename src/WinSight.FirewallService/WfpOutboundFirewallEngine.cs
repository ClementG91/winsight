using WinSight.Firewall;

namespace WinSight.FirewallService;

/// <summary>
/// The mandatory service-side WFP truth boundary. Implementations reconcile from the
/// complete desired policy set, verify the complete native state, and remove every
/// WinSight-owned object without relying on policy-store paths.
/// </summary>
public interface IWinSightWfpReconciler
{
    bool IsSupported { get; }

    Task ReconcileExactAsync(
        IReadOnlyList<AppFirewallPolicy> policies,
        CancellationToken cancellationToken = default);

    Task<bool> VerifyExactAsync(
        IReadOnlyList<AppFirewallPolicy> policies,
        CancellationToken cancellationToken = default);

    Task CleanupAllAsync(CancellationToken cancellationToken = default);
}

internal interface IWinSightWfpSession : IDisposable
{
    void Provision();
    void AddBlock(string executablePath);
    void RemoveBlock(string executablePath);
    void ReconcileExact(IReadOnlyList<AppFirewallPolicy> policies);
    bool VerifyExact(IReadOnlyList<AppFirewallPolicy> policies);
    void CleanupAll();
}

/// <summary>
/// The service-owned dynamic WFP session. Mutations use its long-lived handle, while exact reads
/// deliberately use an independent short-lived session. A timed-out native read can therefore
/// finish in the background without retaining the sole mutation session or preventing recovery.
/// </summary>
internal sealed class DynamicWinSightWfpSession : IWinSightWfpSession
{
    private readonly object _gate = new();
    private WfpProvisioning.SafeWfpEngineSession? _engine = WfpProvisioning.OpenDynamicSession();

    public void Provision() => Invoke(WfpProvisioning.Provision);

    public void AddBlock(string executablePath) =>
        Invoke(engine => WfpProvisioning.AddBlockFilter(engine, executablePath));

    public void RemoveBlock(string executablePath) =>
        Invoke(engine => WfpProvisioning.RemoveBlockFilter(engine, executablePath));

    public void ReconcileExact(IReadOnlyList<AppFirewallPolicy> policies) =>
        Invoke(engine => WfpProvisioning.ReconcileExact(engine, policies));

    public bool VerifyExact(IReadOnlyList<AppFirewallPolicy> policies) =>
        WfpProvisioning.VerifyExact(policies);

    public void CleanupAll() => Invoke(WfpProvisioning.CleanupAll);

    public void Dispose()
    {
        WfpProvisioning.SafeWfpEngineSession? engine;
        lock (_gate)
        {
            engine = _engine;
            _engine = null;
        }
        engine?.Dispose();
    }

    private void Invoke(Action<IntPtr> operation)
    {
        lock (_gate)
        {
            var engine = _engine ?? throw new ObjectDisposedException(nameof(DynamicWinSightWfpSession));
            engine.Invoke(operation);
        }
    }
}

/// <summary>
/// The real WFP-backed outbound firewall engine. It maps per-application policies to WFP
/// filters: a <see cref="OutboundAction.Block"/> policy installs a per-app block filter
/// (IPv4 and IPv6), while <see cref="OutboundAction.Allow"/> and
/// <see cref="OutboundAction.Ask"/> ensure the app is not blocked. It idempotently
/// provisions the WinSight provider/sublayer, so applying a policy is self-contained. Only
/// the privileged service uses this; it is never wired into the unprivileged dashboard.
///
/// The service authority creates this backend lazily, only after trusted storage proves
/// that enforcement or narrowly scoped WinSight cleanup requires native access.
/// </summary>
public sealed class WfpOutboundFirewallEngine : IOutboundFirewallEngine, IWinSightWfpReconciler, IDisposable
{
    private readonly object _lifetimeGate = new();
    private readonly Func<IWinSightWfpSession> _sessionFactory;
    private IWinSightWfpSession? _session;
    private bool _disposed;

    public WfpOutboundFirewallEngine() : this(static () => new DynamicWinSightWfpSession())
    {
    }

    internal WfpOutboundFirewallEngine(Func<IWinSightWfpSession> sessionFactory) =>
        _sessionFactory = sessionFactory ?? throw new ArgumentNullException(nameof(sessionFactory));

    /// <summary>WFP is available on every supported Windows baseline.</summary>
    public bool IsSupported => true;

    public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
        cancellationToken.ThrowIfCancellationRequested();

        if (policy.Enabled && policy.Action == OutboundAction.Block)
        {
            var session = GetSession();
            session.Provision();
            session.AddBlock(policy.ExecutablePath);
        }
        else
        {
            // Allow / Ask: make sure any earlier block for this app is lifted.
            GetSession().RemoveBlock(policy.ExecutablePath);
        }
        return Task.CompletedTask;
    }

    public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        cancellationToken.ThrowIfCancellationRequested();

        GetSession().RemoveBlock(executablePath);
        return Task.CompletedTask;
    }

    public Task ReconcileExactAsync(
        IReadOnlyList<AppFirewallPolicy> policies,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policies);
        cancellationToken.ThrowIfCancellationRequested();
        GetSession().ReconcileExact(policies);
        return Task.CompletedTask;
    }

    public Task<bool> VerifyExactAsync(
        IReadOnlyList<AppFirewallPolicy> policies,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policies);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(GetSession().VerifyExact(policies));
    }

    public Task CleanupAllAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        GetSession().CleanupAll();
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        IWinSightWfpSession? session;
        lock (_lifetimeGate)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            session = _session;
            _session = null;
        }
        session?.Dispose();
    }

    private IWinSightWfpSession GetSession()
    {
        lock (_lifetimeGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _session ??= _sessionFactory()
                ?? throw new InvalidOperationException("The WFP session factory returned null.");
        }
    }
}
