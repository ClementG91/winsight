using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace WinSight.FirewallService;

/// <summary>
/// Registers and removes the WinSight firewall Windows service through the Service
/// Control Manager. Installation is an explicit, elevated, opt-in step: the per-user
/// application setup never installs it, and the installed service is demand-start and
/// audit-only (it installs no WFP filter). The SCM stores the binary path verbatim, so
/// a spaced install directory is quoted correctly and cannot be re-parsed by a shell.
/// </summary>
public static partial class FirewallServiceInstaller
{
    public const string ServiceName = "WinSightFirewall";
    public const string DisplayName = "WinSight Firewall";
    public const string Description =
        "Audit-only outbound firewall policy service for WinSight. Installs no WFP filter.";

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
        ArgumentNullException.ThrowIfNull(trustInspector);
        ArgumentNullException.ThrowIfNull(serviceControlManager);
        var evidence = trustInspector.InspectExecutableEvidence(executablePath);
        if (!evidence.Decision.IsTrusted)
        {
            throw new InvalidOperationException(
                $"Service path rejected [{evidence.Decision.Code}]: {evidence.Decision.Message}");
        }
        var preUse = trustInspector.Revalidate(evidence);
        if (!preUse.IsTrusted)
        {
            throw new InvalidOperationException($"Service path rejected [{preUse.Code}]: {preUse.Message}");
        }
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
            if (service == IntPtr.Zero)
            {
                return false;
            }
            NativeMethods.CloseServiceHandle(service);
            return true;
        }
        finally
        {
            NativeMethods.CloseServiceHandle(manager);
        }
    }

    /// <summary>
    /// Switches the installed service between auto-start (runs on boot, so enforcement
    /// survives a reboot) and demand-start. Returns false when the service is not
    /// installed. A firewall that stops enforcing after a reboot is a hole, so enforcement
    /// makes the service auto-start.
    /// </summary>
    public static bool TrySetAutoStart(bool autoStart)
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
                if (error == ErrorServiceDoesNotExist)
                {
                    return false;
                }
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
                return true;
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

    internal static void SetDescription(IntPtr service, string description)
    {
        var descriptionPtr = Marshal.StringToHGlobalUni(description);
        try
        {
            var info = new ServiceDescription { Description = descriptionPtr };
            // Best-effort: a failure to set the cosmetic description never fails install.
            NativeMethods.ChangeServiceConfig2W(service, ServiceConfigDescription, ref info);
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
