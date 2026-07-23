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

    public static void Install(
        string executablePath,
        IServicePathTrustInspector trustInspector,
        IServiceControlManager serviceControlManager)
    {
        ArgumentNullException.ThrowIfNull(serviceControlManager);
        var evidence = InspectAndRevalidateExecutable(executablePath, trustInspector);
        var binaryPath = BuildBinaryPath(evidence.CanonicalPath);
        using var registration = serviceControlManager.Create(binaryPath);
        try
        {
            registration.SetDescription(Description);
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

    /// <summary>Deletes the service. Throws if it is not installed.</summary>
    public static void Uninstall()
    {
        var manager = NativeMethods.OpenSCManagerW(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        try
        {
            var service = NativeMethods.OpenServiceW(manager, ServiceName, ServiceDelete);
            if (service == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                throw error == ErrorServiceDoesNotExist
                    ? new InvalidOperationException("The WinSight firewall service is not installed.")
                    : new Win32Exception(error);
            }
            try
            {
                if (!NativeMethods.DeleteService(service))
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
    private const uint ServiceAllAccess = 0xF01FF;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceChangeConfig = 0x0002;
    private const uint ServiceDelete = 0x00010000;
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceAutoStart = 0x00000002;
    private const uint ServiceDemandStart = 0x00000003;
    private const uint ServiceErrorNormal = 0x00000001;
    private const uint ServiceConfigDescription = 1;
    private const uint ServiceNoChange = 0xFFFFFFFF;
    private const int ErrorServiceExists = 1073;
    private const int ErrorServiceDoesNotExist = 1060;

    [StructLayout(LayoutKind.Sequential)]
    internal struct ServiceDescription
    {
        public IntPtr Description;
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
        internal static partial bool CloseServiceHandle(IntPtr handle);

        [LibraryImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool ChangeServiceConfig2W(IntPtr service, uint infoLevel, ref ServiceDescription info);

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
        PathTrustCode.Trusted => InspectionFailed,
        _ => InspectionFailed,
    };
}

public interface IServiceRegistration : IDisposable
{
    void SetDescription(string description);
    bool Delete();
}

public interface IServiceControlManager
{
    IServiceRegistration Create(string binaryPath);
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
                manager, FirewallServiceInstaller.ServiceName, FirewallServiceInstaller.DisplayName, 0xF01FF,
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

    private sealed class WindowsServiceRegistration(IntPtr handle) : IServiceRegistration
    {
        public void SetDescription(string description) => FirewallServiceInstaller.SetDescription(handle, description);
        public bool Delete() => FirewallServiceInstaller.NativeMethods.DeleteService(handle);
        public void Dispose() => FirewallServiceInstaller.NativeMethods.CloseServiceHandle(handle);
    }
}
