using System.Runtime.InteropServices;

using Microsoft.Win32;

namespace WinSight.CodeIntegrity;

/// <summary>
/// Reads the machine's enforcement posture from the kernel and the firmware state.
/// </summary>
/// <remarks>
/// The kernel is asked directly rather than the policy registry, for the same reason the firewall
/// scan checks WFP's effective filters rather than WinSight's stored intent: the registry records
/// what somebody configured, and the kernel records what is actually being enforced. A pending
/// reboot, a policy that failed to apply, or a hypervisor that could not start all make the two
/// disagree — and the second one is the answer that matters.
///
/// Everything here works unelevated, which is the point: a posture check an ordinary user cannot
/// run is a posture check that does not get run.
/// </remarks>
public sealed class CodeIntegrityReader
{
    // NtQuerySystemInformation classes. Fixed by Windows.
    private const int SystemCodeIntegrityInformation = 103;
    private const int SystemKernelDebuggerInformation = 35;

    public CodeIntegrityState Read()
    {
        var (options, read) = ReadKernelOptions();
        return new CodeIntegrityState(
            (CodeIntegrityOptions)options,
            options,
            read,
            ReadSecureBoot(),
            ReadKernelDebugger());
    }

    private static (uint Options, bool Read) ReadKernelOptions()
    {
        try
        {
            var info = new SystemCodeIntegrityInformationData
            {
                Length = (uint)Marshal.SizeOf<SystemCodeIntegrityInformationData>(),
            };
            var status = NativeMethods.NtQuerySystemInformation(
                SystemCodeIntegrityInformation, ref info, Marshal.SizeOf<SystemCodeIntegrityInformationData>(), out _);
            // Any non-success status leaves the posture undetermined; it must not read as "off".
            return status == 0 ? (info.CodeIntegrityOptions, true) : (0u, false);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return (0u, false);
        }
    }

    private static ProtectionReading ReadKernelDebugger()
    {
        try
        {
            var info = default(SystemKernelDebuggerInformationData);
            var status = NativeMethods.NtQuerySystemInformation(
                SystemKernelDebuggerInformation, ref info, Marshal.SizeOf<SystemKernelDebuggerInformationData>(), out _);
            if (status != 0)
            {
                return ProtectionReading.Unknown;
            }
            // "Attached and active" needs both: a debugger can be enabled in the boot configuration
            // while nothing is connected, which is not the same as one listening right now.
            return info.KernelDebuggerEnabled != 0 && info.KernelDebuggerNotPresent == 0
                ? ProtectionReading.On
                : ProtectionReading.Off;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return ProtectionReading.Unknown;
        }
    }

    private static ProtectionReading ReadSecureBoot()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            // The value is absent on firmware without Secure Boot at all (legacy BIOS/CSM), which
            // is "cannot say", not "switched off".
            return key?.GetValue("UEFISecureBootEnabled") is int enabled
                ? enabled != 0 ? ProtectionReading.On : ProtectionReading.Off
                : ProtectionReading.Unknown;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                     or UnauthorizedAccessException
                                     or IOException)
        {
            return ProtectionReading.Unknown;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SystemCodeIntegrityInformationData
    {
        public uint Length;
        public uint CodeIntegrityOptions;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SystemKernelDebuggerInformationData
    {
        public byte KernelDebuggerEnabled;
        public byte KernelDebuggerNotPresent;
    }

    private static class NativeMethods
    {
        [DllImport("ntdll.dll")]
        internal static extern int NtQuerySystemInformation(
            int systemInformationClass,
            ref SystemCodeIntegrityInformationData info,
            int length,
            out int returnLength);

        [DllImport("ntdll.dll")]
        internal static extern int NtQuerySystemInformation(
            int systemInformationClass,
            ref SystemKernelDebuggerInformationData info,
            int length,
            out int returnLength);
    }
}
