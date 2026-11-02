using System.Security.AccessControl;
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
/// user's SID, so a second account in the same session keeps its own instance. Each exact opened
/// handle must have this token user's owner SID and the supported private DACL before it can
/// suppress a launch or carry activation. Untrusted or inaccessible coordination falls back to an
/// independent primary. This point-in-time check does not authenticate a particular executable or
/// defend against hostile same-user/admin changes. The Explorer signature window and the smoke
/// test start no monitors and are not subject to this.
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
        var user = CurrentUser();
        if (user is null)
        {
            return new DashboardSingleInstance(isPrimary: true, mutex: null, activation: null);
        }
        scope ??= user.Value;
        Mutex? mutex = null;
        EventWaitHandle? activation = null;
        try
        {
            mutex = MutexAcl.Create(false, MutexName(scope), out var createdNew,
                DashboardObjectSecurity.MutexDescriptor(user));
            if (!DashboardObjectSecurity.IsTrusted(mutex.SafeWaitHandle, user, (int)MutexRights.FullControl))
            {
                return new DashboardSingleInstance(isPrimary: true, mutex: null, activation: null);
            }
            if (!createdNew)
            {
                // Keep the verified lifetime handle alive through the existing-event request.
                RequestActivation(scope, user);
                return new DashboardSingleInstance(isPrimary: false, mutex: null, activation: null);
            }
            try
            {
                activation = EventWaitHandleAcl.Create(false, EventResetMode.AutoReset,
                    ActivationName(scope), out _, DashboardObjectSecurity.EventDescriptor(user));
                if (!DashboardObjectSecurity.IsTrusted(activation.SafeWaitHandle, user, (int)EventWaitHandleRights.FullControl))
                {
                    activation.Dispose();
                    activation = null;
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or WaitHandleCannotBeOpenedException
                                         or System.Security.SecurityException)
            {
                activation?.Dispose();
                activation = null;
            }
            var result = new DashboardSingleInstance(isPrimary: true, mutex, activation);
            mutex = null;
            activation = null;
            return result;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or WaitHandleCannotBeOpenedException
                                     or System.Security.SecurityException)
        {
            // An unknown object cannot be allowed to suppress independent monitoring.
            return new DashboardSingleInstance(isPrimary: true, mutex: null, activation: null);
        }
        finally
        {
            activation?.Dispose();
            mutex?.Dispose();
        }
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

    private static void RequestActivation(string scope, SecurityIdentifier user)
    {
        try
        {
            using var activation = EventWaitHandleAcl.OpenExisting(ActivationName(scope),
                EventWaitHandleRights.ReadPermissions | EventWaitHandleRights.Modify);
            if (DashboardObjectSecurity.IsTrusted(activation.SafeWaitHandle, user, (int)EventWaitHandleRights.FullControl))
            {
                activation.Set();
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or WaitHandleCannotBeOpenedException
                                     or System.Security.SecurityException)
        {
            // The first instance is starting up or shutting down; nothing more can be done from here.
        }
    }

    private static SecurityIdentifier? CurrentUser()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.User;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null;
        }
    }
}
