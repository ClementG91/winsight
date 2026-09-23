using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WinSight.FirewallService;

public static partial class WfpProvisioning
{
    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmDisplayData0
    {
        public IntPtr Name;
        public IntPtr Description;
    }

    // FWPM_SESSION0 contains output-only identity fields after the caller-controlled flags and
    // transaction timeout. They still belong in the managed layout: omitting them shortens the
    // buffer BFE receives and makes the interop architecture-dependent.
    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmSession0
    {
        public Guid SessionKey;
        public FwpmDisplayData0 DisplayData;
        public uint Flags;
        public uint TransactionWaitTimeoutMilliseconds;
        public uint ProcessId;
        public IntPtr Sid;
        public IntPtr Username;
        public int KernelMode;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpByteBlob
    {
        public uint Size;
        public IntPtr Data;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmProvider0
    {
        public Guid ProviderKey;
        public FwpmDisplayData0 DisplayData;
        public uint Flags;
        public FwpByteBlob ProviderData;
        public IntPtr ServiceName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmSublayer0
    {
        public Guid SubLayerKey;
        public FwpmDisplayData0 DisplayData;
        public uint Flags;
        public IntPtr ProviderKey;
        public FwpByteBlob ProviderData;
        public ushort Weight;
    }

    // FWP_VALUE0: a tagged 8-byte union. Only FWP_EMPTY (type 0, value 0) is used here,
    // which asks WFP to auto-assign the filter weight.
    [StructLayout(LayoutKind.Sequential)]
    private struct FwpValue0
    {
        public uint Type;
        public ulong Value;
    }

    // FWPM_ACTION0: action type plus a GUID union (callout/filter type), unused for PERMIT.
    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmAction0
    {
        public uint Type;
        public Guid FilterOrCalloutKey;
    }

    // FWP_CONDITION_VALUE0: a tagged value. For an app-id match the type is
    // FWP_BYTE_BLOB_TYPE and the value is a pointer to the app-id byte blob.
    [StructLayout(LayoutKind.Sequential)]
    private struct FwpConditionValue0
    {
        public uint Type;
        public IntPtr Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmFilterCondition0
    {
        public Guid FieldKey;
        public uint MatchType;
        public FwpConditionValue0 ConditionValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmFilter0
    {
        public Guid FilterKey;
        public FwpmDisplayData0 DisplayData;
        public uint Flags;
        public IntPtr ProviderKey;
        public FwpByteBlob ProviderData;
        public Guid LayerKey;
        public Guid SubLayerKey;
        public FwpValue0 Weight;
        public uint NumFilterConditions;
        public IntPtr FilterCondition;
        public FwpmAction0 Action;

        // union { UINT64 rawContext; GUID providerContextKey; }: zeroed (no context).
        public Guid ProviderContextKey;
        public IntPtr Reserved;
        public ulong FilterId;
        public FwpValue0 EffectiveWeight;
    }

    /// <summary>
    /// Owns a dynamic BFE session. SafeHandle supplies a finalizer as a last-resort RPC rundown if
    /// managed teardown is skipped; normal service disposal still closes it deterministically.
    /// </summary>
    internal sealed class SafeWfpEngineSession : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeWfpEngineSession(IntPtr engine) : base(ownsHandle: true) => SetHandle(engine);

        internal void Invoke(Action<IntPtr> operation)
        {
            ArgumentNullException.ThrowIfNull(operation);
            var retained = false;
            try
            {
                DangerousAddRef(ref retained);
                operation(DangerousGetHandle());
            }
            finally
            {
                if (retained)
                {
                    DangerousRelease();
                }
            }
        }

        protected override bool ReleaseHandle() => NativeMethods.FwpmEngineClose0(handle) == 0;
    }

    private static partial class NativeMethods
    {
        [LibraryImport("fwpuclnt.dll", StringMarshalling = StringMarshalling.Utf16)]
        internal static partial uint FwpmEngineOpen0(
            string? serverName, uint authnService, IntPtr authIdentity, IntPtr session, out IntPtr engineHandle);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmEngineClose0(IntPtr engineHandle);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmTransactionCommit0(IntPtr engineHandle);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmTransactionAbort0(IntPtr engineHandle);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmProviderAdd0(IntPtr engineHandle, ref FwpmProvider0 provider, IntPtr sd);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmProviderDeleteByKey0(IntPtr engineHandle, ref Guid key);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmProviderGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr provider);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmSubLayerAdd0(IntPtr engineHandle, ref FwpmSublayer0 subLayer, IntPtr sd);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmSubLayerDeleteByKey0(IntPtr engineHandle, ref Guid key);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmSubLayerGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr subLayer);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmFilterAdd0(IntPtr engineHandle, ref FwpmFilter0 filter, IntPtr sd, out ulong id);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmFilterDeleteByKey0(IntPtr engineHandle, ref Guid key);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmFilterGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr filter);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmFilterCreateEnumHandle0(
            IntPtr engineHandle, IntPtr enumTemplate, out IntPtr enumHandle);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmFilterEnum0(
            IntPtr engineHandle,
            IntPtr enumHandle,
            uint numEntriesRequested,
            out IntPtr entries,
            out uint numEntriesReturned);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial uint FwpmFilterDestroyEnumHandle0(IntPtr engineHandle, IntPtr enumHandle);

        [LibraryImport("fwpuclnt.dll", StringMarshalling = StringMarshalling.Utf16)]
        internal static partial uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial void FwpmFreeMemory0(ref IntPtr p);
    }
}
