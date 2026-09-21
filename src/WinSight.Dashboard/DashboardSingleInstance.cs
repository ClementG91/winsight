using System.Security.Principal;

namespace WinSight.Dashboard;

/// <summary>
/// Keeps one interactive dashboard per user and session. A second launch asks the first to show
/// itself and exits.
/// </summary>
/// <remarks>
/// <b>Why.</b> Every interactive dashboard starts Guardian, camera/microphone monitoring and, when it
/// is enabled, ransomware protection. Two of them meant every startup item raised two decision
/// windows and two journal entries, two tray icons, and two processes saving their own snapshots of
/// the same per-user state in turn. A shortcut clicked twice, or the Start menu while the tray copy
/// runs, was enough.
///
/// <b>Scope.</b> The names live in the <c>Local\</c> namespace, which is per session, and carry the
/// user's SID, so a second account in the same session keeps its own instance. Only a mutex this
/// account can open counts as an existing instance: a name another account created and this one
/// cannot open is not a WinSight dashboard of this user, and must not be able to stop one from
/// starting. The Explorer signature window and the smoke test start no monitors and are not subject
/// to this.
/// </remarks>
internal sealed class DashboardSingleInstance : IDisposable
{
    private readonly Mutex? _mutex;
    private readonly EventWaitHandle? _activation;
    private RegisteredWaitHandle? _registration;
    private int _disposed;

    private DashboardSingleInstance(bool isPrimary, Mutex? mutex, EventWaitHandle? activation)
    {
        IsPrimary = isPrimary;
        _mutex = mutex;
        _activation = activation;
    }

    /// <summary>True when this process is the dashboard for its user and session.</summary>
    public bool IsPrimary { get; }

    internal static string MutexName(string scope) => $@"Local\WinSight.Dashboard.{scope}";

    internal static string ActivationName(string scope) => $@"Local\WinSight.Dashboard.Activate.{scope}";

    /// <summary>
    /// Claims the instance for <paramref name="scope"/> (the current user's SID by default), or, when
    /// another dashboard of this user already holds it, asks that one to show itself.
    /// </summary>
    public static DashboardSingleInstance Acquire(string? scope = null)
    {
        scope ??= CurrentUserScope();
        Mutex mutex;
        bool createdNew;
        try
        {
            mutex = new Mutex(initiallyOwned: false, MutexName(scope), out createdNew);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or WaitHandleCannotBeOpenedException)
        {
            // Somebody else's object under this name. Running without the guarantee is better than
            // letting an object this account cannot even open keep the dashboard from starting.
            return new DashboardSingleInstance(isPrimary: true, mutex: null, activation: null);
        }

        if (createdNew)
        {
            try
            {
                var activation = new EventWaitHandle(
                    initialState: false, EventResetMode.AutoReset, ActivationName(scope));
                return new DashboardSingleInstance(isPrimary: true, mutex, activation);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or WaitHandleCannotBeOpenedException)
            {
                // The instance is still this one; it simply cannot be raised by a second launch.
                return new DashboardSingleInstance(isPrimary: true, mutex, activation: null);
            }
        }

        mutex.Dispose();
        RequestActivation(scope);
        return new DashboardSingleInstance(isPrimary: false, mutex: null, activation: null);
    }

    /// <summary>
    /// Runs <paramref name="onActivationRequested"/> (on a thread-pool thread) each time a second
    /// launch asks this instance to show itself.
    /// </summary>
    public void OnActivationRequested(Action onActivationRequested)
    {
        ArgumentNullException.ThrowIfNull(onActivationRequested);
        if (!IsPrimary || _activation is null || _registration is not null)
        {
            return;
        }
        _registration = ThreadPool.RegisterWaitForSingleObject(
            _activation,
            (_, _) => onActivationRequested(),
            state: null,
            Timeout.Infinite,
            executeOnlyOnce: false);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        _registration?.Unregister(null);
        _activation?.Dispose();
        _mutex?.Dispose();
    }

    private static void RequestActivation(string scope)
    {
        try
        {
            using var activation = EventWaitHandle.OpenExisting(ActivationName(scope));
            activation.Set();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or WaitHandleCannotBeOpenedException)
        {
            // The first instance is starting up or shutting down; nothing more can be done from here.
        }
    }

    private static string CurrentUserScope()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.User?.Value ?? Environment.UserName;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return Environment.UserName;
        }
    }
}
