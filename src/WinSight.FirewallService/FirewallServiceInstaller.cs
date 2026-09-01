using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Principal;

[assembly: InternalsVisibleTo("WinSight.FirewallService.Tests")]

namespace WinSight.FirewallService;

/// <summary>
/// Registers and removes the WinSight firewall Windows service through the Service
/// Control Manager. Installation is an explicit, elevated, opt-in step: the per-user
/// application setup never installs it, and the installed service is demand-start.
/// Enforcement requires an explicit privileged transition and is reported separately
/// from the desired persisted mode. The SCM stores the binary path verbatim, so a
/// spaced install directory is quoted correctly and cannot be re-parsed by a shell.
/// </summary>
public static partial class FirewallServiceInstaller
{
    public const string ServiceName = "WinSightFirewall";
    public const string DisplayName = "WinSight Firewall";
    public const string Description =
        "WinSight opt-in outbound firewall service with separate desired and effective runtime state.";

    /// <summary>
    /// The SCM binary path: the quoted executable plus the run verb, as one string the
    /// SCM stores literally. Quoting keeps a spaced install path from being split.
    /// </summary>
    public static string BuildBinaryPath(string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        return $"\"{executablePath}\" run";
    }

    /// <summary>True when the current process runs with local Administrator rights.</summary>
    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>Creates the demand-start, LocalSystem service pointing at this executable.</summary>
    public static void Install(string executablePath)
        => Install(executablePath, new WindowsServicePathTrustInspector(), new WindowsServiceControlManager());

    /// <summary>Injectable trust inspection keeps denial tests entirely outside SCM.</summary>
    public static void Install(string executablePath, IServicePathTrustInspector trustInspector)
        => Install(executablePath, trustInspector, new WindowsServiceControlManager());

    /// <param name="provisionStorage">
    /// Creates and hardens the policy directory. Injected so the SCM-facing tests do not have to
    /// touch <c>C:\ProgramData</c>, and so a caller that has already provisioned can say so.
    /// </param>
    public static void Install(
        string executablePath,
        IServicePathTrustInspector trustInspector,
        IServiceControlManager serviceControlManager,
        Action? provisionStorage = null)
    {
        ArgumentNullException.ThrowIfNull(serviceControlManager);
        var evidence = InspectAndRevalidateExecutable(executablePath, trustInspector);
        ProvisionPolicyStorage(provisionStorage ?? FirewallServicePaths.ProvisionDefaultDirectoryAction);
        var binaryPath = BuildBinaryPath(evidence.CanonicalPath);
        using var registration = serviceControlManager.Create(binaryPath);
        try
        {
            registration.SetDescription(Description);
            registration.ConfigureSecurityProfile();
        }
        catch (Exception postCreateFailure)
        {
            ThrowAfterCheckedRollback(
                registration,
                ServiceInstallTrustCode.PostCreateOperationRolledBack,
                "Service registration was rolled back after post-create configuration failed.",
                postCreateFailure);
        }
        PathTrustDecision postUse;
        try { postUse = trustInspector.Revalidate(evidence); }
        catch (Exception)
        { postUse = PathTrustDecision.Deny(PathTrustCode.InspectionFailed); }
        if (!postUse.IsTrusted)
        {
            ThrowAfterCheckedRollback(
                registration,
                ServiceInstallTrustCode.PathChangedRolledBack,
                $"Service path rejected [{postUse.Code}] and registration was rolled back.");
        }
    }

    /// <summary>
    /// Creates and hardens the policy directory while the caller still holds an administrator token.
    /// </summary>
    /// <remarks>
    /// <b>Why install time and not first start.</b> The default ACL on <c>C:\ProgramData</c> lets
    /// <c>BUILTIN\Users</c> create subdirectories and materialises CREATOR OWNER as a FullControl
    /// entry for whoever created one. A standard user can therefore create
    /// <c>C:\ProgramData\WinSight</c> first, become its owner, and remove SYSTEM and Administrators.
    /// The service cannot take it back: its token is deliberately restricted to
    /// SeChangeNotify / SeImpersonate / SeSystemProfile, so it holds neither SeTakeOwnership nor
    /// SeRestore, and startup fails with <c>[FW_STORAGE_PROVISIONING_FAILED]</c> on every boot -
    /// persistently, and looking to the operator exactly like a machine where the service was never
    /// installed.
    ///
    /// Doing it here closes the window for the ordinary flow, because <c>install</c> runs elevated
    /// and an administrator token <i>can</i> reclaim the directory. It also surfaces the problem
    /// while an operator is watching, rather than leaving a service that registers cleanly and then
    /// never starts.
    ///
    /// Restoring those privileges to the service token was the other option and is worse: it would
    /// give a LocalSystem service the ability to take ownership of anything on the machine, to
    /// handle a case an elevated install already handles.
    /// </remarks>
    private static void ProvisionPolicyStorage(Action provision)
    {
        try
        {
            provision();
        }
        catch (PolicyStorageTrustException refusal)
        {
            throw new ServiceInstallTrustException(
                ServiceInstallTrustCode.PolicyStorageRefused,
                $"Policy storage was refused by the trust inspection [{refusal.Code}]; "
                + "another principal owns it and the service would never start.",
                refusal);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or IOException
                                     or InvalidOperationException)
        {
            throw new ServiceInstallTrustException(
                ServiceInstallTrustCode.PolicyStorageRefused,
                "Policy storage could not be provisioned; the service would never start.",
                ex);
        }
    }

    internal static PathTrustEvidence InspectAndRevalidateExecutable(
        string executablePath,
        IServicePathTrustInspector trustInspector)
    {
        ArgumentNullException.ThrowIfNull(trustInspector);
        var evidence = trustInspector.InspectExecutableEvidence(executablePath);
        if (!evidence.Decision.IsTrusted)
        {
            throw new ServicePathTrustException(evidence.Decision.Code);
        }
        var preUse = trustInspector.Revalidate(evidence);
        if (!preUse.IsTrusted)
        {
            throw new ServicePathTrustException(preUse.Code);
        }
        return evidence;
    }

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void ThrowAfterCheckedRollback(
        IServiceRegistration registration,
        ServiceInstallTrustCode successCode,
        string message,
        Exception? cause = null)
    {
        var rolledBack = false;
        Exception? rollbackFailure = null;
        try { rolledBack = registration.Delete(); }
        catch (Exception ex) { rollbackFailure = ex; }
        if (!rolledBack)
        {
            throw new ServiceInstallTrustException(
                ServiceInstallTrustCode.RollbackFailed,
                "Service registration rollback failed after a post-create operation.",
                rollbackFailure ?? cause);
        }
        throw new ServiceInstallTrustException(successCode, message, cause);
    }

    /// <summary>
    /// Stops the service, proves the WinSight WFP namespace empty, then deletes registration.
    /// A failure leaves the stopped service registered so the operator still has a recovery path;
    /// it never deletes the control plane while filtering residue is unaccounted for.
    /// </summary>
    public static void Uninstall() =>
        Uninstall(new WindowsServiceControlManager(), WfpProvisioning.CleanupAll);

    internal static void Uninstall(
        IServiceControlManager serviceControlManager,
        Action cleanupWfp)
    {
        ArgumentNullException.ThrowIfNull(serviceControlManager);
        ArgumentNullException.ThrowIfNull(cleanupWfp);
        using var registration = serviceControlManager.OpenForRemoval();
        registration.StopAndWait(TimeSpan.FromSeconds(30));
        cleanupWfp();
        if (!registration.Delete())
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    /// <summary>True when the service is registered with the SCM.</summary>
    public static bool IsInstalled()
    {
        var manager = NativeMethods.OpenSCManagerW(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        try
        {
            var service = NativeMethods.OpenServiceW(manager, ServiceName, ServiceQueryConfig);
            var installed = InterpretServiceQueryResult(service, Marshal.GetLastWin32Error());
            if (!installed) return false;
            NativeMethods.CloseServiceHandle(service);
            return true;
        }
        finally
        {
            NativeMethods.CloseServiceHandle(manager);
        }
    }

    internal static bool InterpretServiceQueryResult(IntPtr service, int error)
    {
        if (service != IntPtr.Zero) return true;
        if (error == ErrorServiceDoesNotExist) return false;
        throw new Win32Exception(error);
    }

    /// <summary>
    /// Switches the installed service between auto-start (runs on boot, so enforcement
    /// survives a reboot) and demand-start. Absence or any other SCM failure is an error:
    /// start mode is part of the serialized enforcement transaction, never best effort.
    /// </summary>
    public static void SetStartMode(bool autoStart)
    {
        var manager = NativeMethods.OpenSCManagerW(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        try
        {
            var service = NativeMethods.OpenServiceW(manager, ServiceName, ServiceChangeConfig);
            if (service == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error);
            }
            try
            {
                var startType = autoStart ? ServiceAutoStart : ServiceDemandStart;
                if (!NativeMethods.ChangeServiceConfigW(
                        service, ServiceNoChange, startType, ServiceNoChange,
                        null, null, IntPtr.Zero, null, null, null, null))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                NativeMethods.CloseServiceHandle(service);
            }
        }
        finally
        {
            NativeMethods.CloseServiceHandle(manager);
        }
    }

    internal delegate bool ChangeServiceDescription(
        IntPtr service,
        uint infoLevel,
        ref ServiceDescription info);

    internal static void SetDescription(IntPtr service, string description) =>
        SetDescription(service, description, NativeMethods.ChangeServiceConfig2W, Marshal.GetLastWin32Error);

    internal static void SetDescription(
        IntPtr service,
        string description,
        ChangeServiceDescription changeDescription,
        Func<int> getLastError)
    {
        ArgumentNullException.ThrowIfNull(changeDescription);
        ArgumentNullException.ThrowIfNull(getLastError);
        var descriptionPtr = Marshal.StringToHGlobalUni(description);
        try
        {
            var info = new ServiceDescription { Description = descriptionPtr };
            if (!changeDescription(service, ServiceConfigDescription, ref info))
            {
                throw new Win32Exception(getLastError());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(descriptionPtr);
        }
    }

    private const uint ScManagerConnect = 0x0001;
    private const uint ScManagerCreateService = 0x0002;
    private const uint ServiceQueryConfig = 0x0001;
    internal const uint ServiceChangeConfig = 0x0002;
    internal const uint ServiceQueryStatus = 0x0004;
    internal const uint ServiceStop = 0x0020;
    internal const uint ServiceStart = 0x0010;
    internal const uint ServiceDelete = 0x00010000;
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceAutoStart = 0x00000002;
    private const uint ServiceDemandStart = 0x00000003;
    private const uint ServiceErrorNormal = 0x00000001;
    private const uint ServiceConfigDescription = 1;
    private const uint ServiceConfigFailureActions = 2;
    private const uint ServiceConfigFailureActionsFlag = 4;
    private const uint ServiceConfigServiceSidInfo = 5;
    private const uint ServiceConfigRequiredPrivilegesInfo = 6;
    private const uint ServiceSidTypeUnrestricted = 1;
    private const int ScActionRestart = 1;
    internal const uint RecoveryResetPeriodSeconds = 3_600;
    private const uint ServiceNoChange = 0xFFFFFFFF;
    internal const uint ServiceControlStop = 0x00000001;
    internal const uint ServiceStopped = 0x00000001;
    internal const uint ServiceStopPending = 0x00000003;
    private const int ErrorServiceExists = 1073;
    internal const int ErrorServiceDoesNotExist = 1060;
    internal const int ErrorServiceNotActive = 1062;

    [StructLayout(LayoutKind.Sequential)]
    internal struct ServiceDescription
    {
        public IntPtr Description;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ServiceSidInfo
    {
        public uint ServiceSidType;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ServiceRequiredPrivilegesInfo
    {
        public IntPtr RequiredPrivileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ServiceFailureActionsFlag
    {
        public int FailureActionsOnNonCrashFailures;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ScAction
    {
        public int Type;
        public uint DelayMilliseconds;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ServiceFailureActions
    {
        public uint ResetPeriodSeconds;
        public IntPtr RebootMessage;
        public IntPtr Command;
        public uint ActionCount;
        public IntPtr Actions;
    }

    internal static string RequiredPrivilegesMultiString() =>
        "SeChangeNotifyPrivilege\0SeImpersonatePrivilege\0SeSystemProfilePrivilege\0\0";

    internal static ScAction[] RecoveryActions() =>
    [
        new ScAction { Type = ScActionRestart, DelayMilliseconds = 5_000 },
        new ScAction { Type = ScActionRestart, DelayMilliseconds = 30_000 },
        new ScAction { Type = ScActionRestart, DelayMilliseconds = 60_000 },
    ];

    /// <summary>
    /// Applies the service's own security profile: SID type, required privileges and failure
    /// actions.
    /// </summary>
    /// <remarks>
    /// <b>What is deliberately not here.</b> No <c>SetServiceObjectSecurity</c> call, so the service
    /// keeps the SCM's default DACL: reconfiguring or stopping it requires administrator, and
    /// nothing beyond that. The service SID is unrestricted and the process is not protected.
    ///
    /// That is a defensible position for a tool with no kernel driver - an administrator who wants
    /// this service stopped can stop it, and WinSight reports the resulting state honestly rather
    /// than resisting - but it was left to be inferred from a document that is otherwise careful
    /// about privilege boundaries. It is now stated in docs/THREAT_MODEL.md.
    ///
    /// A tighter DACL and a restricted service SID are both worth having and are both changes to a
    /// live SYSTEM service that cannot be exercised outside the VM campaign: getting either wrong
    /// leaves a service an administrator cannot manage, which is a worse outcome than the one being
    /// fixed. They belong to a qualification run.
    /// </remarks>
    internal static void ConfigureSecurityProfile(IntPtr service)
    {
        var sid = new ServiceSidInfo { ServiceSidType = ServiceSidTypeUnrestricted };
        if (!NativeMethods.ChangeServiceSidInfo(service, ServiceConfigServiceSidInfo, ref sid))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var privilegesPtr = Marshal.StringToHGlobalUni(RequiredPrivilegesMultiString());
        try
        {
            var privileges = new ServiceRequiredPrivilegesInfo { RequiredPrivileges = privilegesPtr };
            if (!NativeMethods.ChangeServiceRequiredPrivileges(
                    service, ServiceConfigRequiredPrivilegesInfo, ref privileges))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(privilegesPtr);
        }

        var actionSize = Marshal.SizeOf<ScAction>();
        var actionsPtr = Marshal.AllocHGlobal(actionSize * 3);
        try
        {
            // The SCM repeats the LAST action for every failure beyond the array, so making the
            // third a restart is what turns recovery from "twice, then give up" into "for ever,
            // once a minute". It used to be SC_ACTION_NONE. Combined with a 24-hour reset period
            // that handed an unprivileged squatter the machine: take the pipe name, let the service
            // fail three times over 35 seconds, and outbound enforcement stays off for a day.
            var actions = RecoveryActions();
            for (var index = 0; index < actions.Length; index++)
            {
                Marshal.StructureToPtr(
                    actions[index], IntPtr.Add(actionsPtr, index * actionSize), false);
            }
            var failureActions = new ServiceFailureActions
            {
                // An hour, not a day. The count decides which delay the next failure gets, so a
                // long window meant a service that failed once at boot and then ran perfectly was
                // still treated as a repeat offender the following evening.
                ResetPeriodSeconds = RecoveryResetPeriodSeconds,
                ActionCount = (uint)actions.Length,
                Actions = actionsPtr,
            };
            if (!NativeMethods.ChangeServiceFailureActions(
                    service, ServiceConfigFailureActions, ref failureActions))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(actionsPtr);
        }

        var failureFlag = new ServiceFailureActionsFlag { FailureActionsOnNonCrashFailures = 1 };
        if (!NativeMethods.ChangeServiceFailureActionsFlag(
                service, ServiceConfigFailureActionsFlag, ref failureFlag))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    internal static partial class NativeMethods
    {
        [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
        internal static partial IntPtr OpenSCManagerW(string? machineName, string? databaseName, uint access);

        [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
        internal static partial IntPtr CreateServiceW(
            IntPtr manager, string serviceName, string displayName, uint access,
            uint serviceType, uint startType, uint errorControl,
            string binaryPath, string? loadOrderGroup, IntPtr tagId,
            string? dependencies, string? serviceStartName, string? password);

        [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
        internal static partial IntPtr OpenServiceW(IntPtr manager, string serviceName, uint access);

        [LibraryImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool DeleteService(IntPtr service);

        [LibraryImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool ControlService(
            IntPtr service, uint control, out ServiceStatus serviceStatus);

        [LibraryImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool QueryServiceStatusEx(
            IntPtr service,
            int infoLevel,
            out ServiceStatusProcess serviceStatus,
            int bufferSize,
            out int bytesNeeded);

        [LibraryImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool CloseServiceHandle(IntPtr handle);

        [LibraryImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool ChangeServiceConfig2W(IntPtr service, uint infoLevel, ref ServiceDescription info);

        [LibraryImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool ChangeServiceSidInfo(
            IntPtr service, uint infoLevel, ref ServiceSidInfo info);

        [LibraryImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool ChangeServiceRequiredPrivileges(
            IntPtr service, uint infoLevel, ref ServiceRequiredPrivilegesInfo info);

        [LibraryImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool ChangeServiceFailureActions(
            IntPtr service, uint infoLevel, ref ServiceFailureActions info);

        [LibraryImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool ChangeServiceFailureActionsFlag(
            IntPtr service, uint infoLevel, ref ServiceFailureActionsFlag info);

        [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool ChangeServiceConfigW(
            IntPtr service, uint serviceType, uint startType, uint errorControl,
            string? binaryPath, string? loadOrderGroup, IntPtr tagId,
            string? dependencies, string? serviceStartName, string? password, string? displayName);
    }
}

/// <summary>SCM start-mode boundary injected into the serialized enforcement authority.</summary>
public interface IFirewallServiceStartModeController
{
    void SetAutomatic();
    void SetDemandStart();
}

/// <summary>Production SCM start-mode controller. Every native false return throws.</summary>
public sealed class WindowsFirewallServiceStartModeController : IFirewallServiceStartModeController
{
    public void SetAutomatic() => FirewallServiceInstaller.SetStartMode(autoStart: true);
    public void SetDemandStart() => FirewallServiceInstaller.SetStartMode(autoStart: false);
}

public enum ServiceInstallTrustCode
{
    PathChangedRolledBack,
    PostCreateOperationRolledBack,
    RollbackFailed,

    /// <summary>
    /// The policy directory could not be created or reclaimed. Reported before anything is
    /// registered, because a service that installs and then never starts is worse than one that
    /// refuses with a reason.
    /// </summary>
    PolicyStorageRefused,
}

public sealed class ServiceInstallTrustException : InvalidOperationException
{
    public ServiceInstallTrustException(ServiceInstallTrustCode code, string message) : base(message) => Code = code;
    public ServiceInstallTrustException(ServiceInstallTrustCode code, string message, Exception? innerException)
        : base(message, innerException) => Code = code;
    public ServiceInstallTrustCode Code { get; }
}

/// <summary>A structured executable-path refusal raised before the SCM is called.</summary>
public sealed class ServicePathTrustException : InvalidOperationException
{
    public ServicePathTrustException(PathTrustCode code)
        : base("Service path trust validation failed before SCM registration.") => Code = code;

    public PathTrustCode Code { get; }
}

/// <summary>Fixed external diagnostics for pre-SCM executable-path refusals.</summary>
public static class ServicePathTrustDiagnosticCodes
{
    public const string Trusted = "[FW_INSTALL_PATH_TRUSTED]";
    public const string InvalidPath = "[FW_INSTALL_PATH_INVALID]";
    public const string OutsideMachineData = "[FW_INSTALL_PATH_OUTSIDE_MACHINE_DATA]";
    public const string MissingComponent = "[FW_INSTALL_PATH_MISSING_COMPONENT]";
    public const string ReparsePoint = "[FW_INSTALL_PATH_REPARSE_POINT]";
    public const string UntrustedOwner = "[FW_INSTALL_PATH_UNTRUSTED_OWNER]";
    public const string WritableByUnprivileged = "[FW_INSTALL_PATH_WRITABLE_BY_UNPRIVILEGED]";
    public const string IdentityChanged = "[FW_INSTALL_PATH_IDENTITY_CHANGED]";
    public const string InspectionFailed = "[FW_INSTALL_PATH_INSPECTION_FAILED]";
    public const string NotOnLocalStorage = "[FW_INSTALL_PATH_NOT_LOCAL]";

    public static string ForInstallDenial(PathTrustCode code) => code switch
    {
        PathTrustCode.InvalidPath => InvalidPath,
        PathTrustCode.OutsideProgramData => OutsideMachineData,
        PathTrustCode.MissingComponent => MissingComponent,
        PathTrustCode.ReparsePoint => ReparsePoint,
        PathTrustCode.UntrustedOwner => UntrustedOwner,
        PathTrustCode.WritableByUnprivilegedPrincipal => WritableByUnprivileged,
        PathTrustCode.IdentityChanged => IdentityChanged,
        PathTrustCode.InspectionFailed => InspectionFailed,
        // Its own token: "the inspection failed" would say the check broke, when it in fact
        // refused, and an operator reading a log needs to know which.
        PathTrustCode.NotOnLocalStorage => NotOnLocalStorage,
        PathTrustCode.Trusted => InspectionFailed,
        _ => InspectionFailed,
    };
}

public interface IServiceRegistration : IDisposable
{
    void SetDescription(string description);
    void ConfigureSecurityProfile();
    void StopAndWait(TimeSpan timeout);
    bool Delete();
}

public interface IServiceControlManager
{
    IServiceRegistration Create(string binaryPath);
    IServiceRegistration OpenForRemoval();
}

internal sealed class WindowsServiceControlManager : IServiceControlManager
{
    public IServiceRegistration Create(string binaryPath)
    {
        var manager = FirewallServiceInstaller.NativeMethods.OpenSCManagerW(null, null, 0x0001 | 0x0002);
        if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var service = FirewallServiceInstaller.NativeMethods.CreateServiceW(
                manager, FirewallServiceInstaller.ServiceName, FirewallServiceInstaller.DisplayName,
                FirewallServiceInstaller.ServiceChangeConfig
                    | FirewallServiceInstaller.ServiceDelete
                    | FirewallServiceInstaller.ServiceStart,
                0x10, 0x3, 0x1, binaryPath, null, IntPtr.Zero, null, null, null);
            if (service == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                throw error == 1073 ? new InvalidOperationException("The WinSight firewall service is already installed.") :
                    new Win32Exception(error);
            }
            return new WindowsServiceRegistration(service);
        }
        finally { FirewallServiceInstaller.NativeMethods.CloseServiceHandle(manager); }
    }

    public IServiceRegistration OpenForRemoval()
    {
        var manager = FirewallServiceInstaller.NativeMethods.OpenSCManagerW(null, null, 0x0001);
        if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            const uint removalAccess = FirewallServiceInstaller.ServiceDelete |
                                       FirewallServiceInstaller.ServiceStop |
                                       FirewallServiceInstaller.ServiceQueryStatus;
            var service = FirewallServiceInstaller.NativeMethods.OpenServiceW(
                manager, FirewallServiceInstaller.ServiceName, removalAccess);
            if (service == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                throw error == FirewallServiceInstaller.ErrorServiceDoesNotExist
                    ? new InvalidOperationException("The WinSight firewall service is not installed.")
                    : new Win32Exception(error);
            }
            return new WindowsServiceRegistration(service);
        }
        finally
        {
            FirewallServiceInstaller.NativeMethods.CloseServiceHandle(manager);
        }
    }

    private sealed class WindowsServiceRegistration(IntPtr handle) : IServiceRegistration
    {
        public void SetDescription(string description) => FirewallServiceInstaller.SetDescription(handle, description);
        public void ConfigureSecurityProfile() => FirewallServiceInstaller.ConfigureSecurityProfile(handle);

        public void StopAndWait(TimeSpan timeout)
        {
            if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(2))
            {
                throw new ArgumentOutOfRangeException(nameof(timeout));
            }

            var status = QueryStatus();
            if (status.CurrentState == FirewallServiceInstaller.ServiceStopped)
            {
                return;
            }
            if (status.CurrentState != FirewallServiceInstaller.ServiceStopPending &&
                !FirewallServiceInstaller.NativeMethods.ControlService(
                    handle, FirewallServiceInstaller.ServiceControlStop, out _))
            {
                var error = Marshal.GetLastWin32Error();
                if (error != FirewallServiceInstaller.ErrorServiceNotActive)
                {
                    throw new Win32Exception(error);
                }
            }

            var deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;
            while (Environment.TickCount64 < deadline)
            {
                status = QueryStatus();
                if (status.CurrentState == FirewallServiceInstaller.ServiceStopped)
                {
                    return;
                }
                Thread.Sleep(100);
            }
            throw new TimeoutException("The WinSight firewall service did not stop before the removal deadline.");
        }

        public bool Delete() => FirewallServiceInstaller.NativeMethods.DeleteService(handle);
        public void Dispose() => FirewallServiceInstaller.NativeMethods.CloseServiceHandle(handle);

        private FirewallServiceInstaller.ServiceStatusProcess QueryStatus()
        {
            if (!FirewallServiceInstaller.NativeMethods.QueryServiceStatusEx(
                    handle,
                    0,
                    out var status,
                    Marshal.SizeOf<FirewallServiceInstaller.ServiceStatusProcess>(),
                    out _))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return status;
        }
    }
}
