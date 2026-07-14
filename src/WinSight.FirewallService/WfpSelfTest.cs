using System.Runtime.InteropServices;

namespace WinSight.FirewallService;

/// <summary>The outcome of the read-only WFP interop self-test.</summary>
/// <param name="EngineOpened">Whether a WFP engine session opened.</param>
/// <param name="FilterCount">Existing filters observed (a lower bound; read-only).</param>
/// <param name="ErrorCode">Win32/FWP error, or 0 on success.</param>
public readonly record struct WfpSelfTestResult(bool EngineOpened, int FilterCount, int ErrorCode);

/// <summary>
/// A strictly read-only Windows Filtering Platform interop probe. It opens a WFP engine
/// session and enumerates existing filters to prove the interop and privileges work on a
/// given machine, then closes everything. It NEVER adds, changes or removes a filter,
/// provider or sublayer, so it cannot affect connectivity. This is the safe first step of
/// the Phase 2 WFP work; enforcement interop is developed separately and VM-validated.
/// </summary>
public static partial class WfpSelfTest
{
    // RPC_C_AUTHN_WINNT: the standard authentication service for a local WFP session.
    private const uint RpcCAuthnWinNt = 10;

    public static WfpSelfTestResult Run()
    {
        var openResult = NativeMethods.FwpmEngineOpen0(null, RpcCAuthnWinNt, IntPtr.Zero, IntPtr.Zero, out var engine);
        if (openResult != 0)
        {
            return new WfpSelfTestResult(EngineOpened: false, FilterCount: 0, (int)openResult);
        }

        try
        {
            var createResult = NativeMethods.FwpmFilterCreateEnumHandle0(engine, IntPtr.Zero, out var enumHandle);
            if (createResult != 0)
            {
                return new WfpSelfTestResult(EngineOpened: true, FilterCount: 0, (int)createResult);
            }

            try
            {
                var enumResult = NativeMethods.FwpmFilterEnum0(
                    engine, enumHandle, numEntriesRequested: 4096, out var entries, out var returned);
                if (entries != IntPtr.Zero)
                {
                    NativeMethods.FwpmFreeMemory0(ref entries);
                }
                return new WfpSelfTestResult(EngineOpened: true, (int)returned, enumResult == 0 ? 0 : (int)enumResult);
            }
            finally
            {
                // Cleanup return codes are intentionally discarded; the probe already
                // has its result and there is nothing to recover from on close.
                _ = NativeMethods.FwpmFilterDestroyEnumHandle0(engine, enumHandle);
            }
        }
        finally
        {
            _ = NativeMethods.FwpmEngineClose0(engine);
        }
    }

    private static partial class NativeMethods
    {
        [LibraryImport("fwpuclnt.dll", StringMarshalling = StringMarshalling.Utf16)]
        internal static partial uint FwpmEngineOpen0(
            string? serverName, uint authnService, IntPtr authIdentity, IntPtr session, out IntPtr engineHandle);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmEngineClose0(IntPtr engineHandle);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmFilterCreateEnumHandle0(
            IntPtr engineHandle, IntPtr enumTemplate, out IntPtr enumHandle);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmFilterEnum0(
            IntPtr engineHandle, IntPtr enumHandle, uint numEntriesRequested,
            out IntPtr entries, out uint numEntriesReturned);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmFilterDestroyEnumHandle0(IntPtr engineHandle, IntPtr enumHandle);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial void FwpmFreeMemory0(ref IntPtr p);
    }
}
