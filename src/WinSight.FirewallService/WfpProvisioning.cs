using System.ComponentModel;
using System.Runtime.InteropServices;

namespace WinSight.FirewallService;

/// <summary>
/// Creates and removes the WinSight-owned Windows Filtering Platform provider and
/// sublayer. These are namespace CONTAINERS only: a provider and a sublayer filter no
/// traffic by themselves, so provisioning them cannot block or affect any connection.
/// They are the ownership scope under which audit-only filters will later live.
///
/// Everything runs inside a WFP transaction so it is all-or-nothing, and both objects
/// are non-persistent (flags = 0): a reboot removes them automatically, which is the
/// safest default while the enforcement work is still being validated. All mutation is
/// idempotent (already-exists / not-found are treated as success).
/// </summary>
public static partial class WfpProvisioning
{
    /// <summary>Stable identity of the WinSight WFP provider.</summary>
    public static readonly Guid ProviderKey = new("d7a9b1e0-5c3a-4b8e-9f21-6c0a7e2d1f34");

    /// <summary>Stable identity of the WinSight WFP sublayer.</summary>
    public static readonly Guid SublayerKey = new("d7a9b1e1-5c3a-4b8e-9f21-6c0a7e2d1f34");

    private const string ProviderName = "WinSight";
    private const string ProviderDescription = "WinSight outbound firewall provider (audit-only).";
    private const string SublayerName = "WinSight outbound";
    private const string SublayerDescription =
        "WinSight outbound firewall sublayer (audit-only, no filter installed).";

    private const uint RpcCAuthnWinNt = 10;
    private const uint FwpEProviderNotFound = 0x80320005;
    private const uint FwpESublayerNotFound = 0x80320007;
    private const uint FwpEAlreadyExists = 0x80320009;

    /// <summary>Creates the provider and sublayer (idempotent). Installs no filter.</summary>
    public static void Provision()
    {
        var engine = OpenEngine();
        try
        {
            InTransaction(engine, () =>
            {
                AddProvider(engine);
                AddSublayer(engine);
            });
        }
        finally
        {
            _ = NativeMethods.FwpmEngineClose0(engine);
        }
    }

    /// <summary>Removes the sublayer then the provider (idempotent).</summary>
    public static void Deprovision()
    {
        var engine = OpenEngine();
        try
        {
            InTransaction(engine, () =>
            {
                var sublayerKey = SublayerKey;
                var removeSublayer = NativeMethods.FwpmSubLayerDeleteByKey0(engine, ref sublayerKey);
                if (removeSublayer is not 0 and not FwpESublayerNotFound)
                {
                    throw new Win32Exception((int)removeSublayer);
                }

                var providerKey = ProviderKey;
                var removeProvider = NativeMethods.FwpmProviderDeleteByKey0(engine, ref providerKey);
                if (removeProvider is not 0 and not FwpEProviderNotFound)
                {
                    throw new Win32Exception((int)removeProvider);
                }
            });
        }
        finally
        {
            _ = NativeMethods.FwpmEngineClose0(engine);
        }
    }

    /// <summary>Reports whether the provider and sublayer currently exist.</summary>
    public static (bool Provider, bool Sublayer) Status()
    {
        var engine = OpenEngine();
        try
        {
            var providerKey = ProviderKey;
            var providerExists = NativeMethods.FwpmProviderGetByKey0(engine, ref providerKey, out var provider) == 0;
            if (provider != IntPtr.Zero)
            {
                NativeMethods.FwpmFreeMemory0(ref provider);
            }

            var sublayerKey = SublayerKey;
            var sublayerExists = NativeMethods.FwpmSubLayerGetByKey0(engine, ref sublayerKey, out var sublayer) == 0;
            if (sublayer != IntPtr.Zero)
            {
                NativeMethods.FwpmFreeMemory0(ref sublayer);
            }

            return (providerExists, sublayerExists);
        }
        finally
        {
            _ = NativeMethods.FwpmEngineClose0(engine);
        }
    }

    private static IntPtr OpenEngine()
    {
        var result = NativeMethods.FwpmEngineOpen0(null, RpcCAuthnWinNt, IntPtr.Zero, IntPtr.Zero, out var engine);
        if (result != 0)
        {
            throw new Win32Exception((int)result);
        }
        return engine;
    }

    private static void InTransaction(IntPtr engine, Action body)
    {
        var begin = NativeMethods.FwpmTransactionBegin0(engine, 0);
        if (begin != 0)
        {
            throw new Win32Exception((int)begin);
        }

        var committed = false;
        try
        {
            body();
            var commit = NativeMethods.FwpmTransactionCommit0(engine);
            if (commit != 0)
            {
                throw new Win32Exception((int)commit);
            }
            committed = true;
        }
        finally
        {
            if (!committed)
            {
                _ = NativeMethods.FwpmTransactionAbort0(engine);
            }
        }
    }

    private static void AddProvider(IntPtr engine)
    {
        var name = Marshal.StringToHGlobalUni(ProviderName);
        var description = Marshal.StringToHGlobalUni(ProviderDescription);
        try
        {
            var provider = new FwpmProvider0
            {
                ProviderKey = ProviderKey,
                DisplayData = new FwpmDisplayData0 { Name = name, Description = description },
                Flags = 0,
                ServiceName = IntPtr.Zero,
            };
            var result = NativeMethods.FwpmProviderAdd0(engine, ref provider, IntPtr.Zero);
            if (result is not 0 and not FwpEAlreadyExists)
            {
                throw new Win32Exception((int)result);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(name);
            Marshal.FreeHGlobal(description);
        }
    }

    private static void AddSublayer(IntPtr engine)
    {
        var name = Marshal.StringToHGlobalUni(SublayerName);
        var description = Marshal.StringToHGlobalUni(SublayerDescription);
        var providerKey = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
        try
        {
            Marshal.StructureToPtr(ProviderKey, providerKey, false);
            var sublayer = new FwpmSublayer0
            {
                SubLayerKey = SublayerKey,
                DisplayData = new FwpmDisplayData0 { Name = name, Description = description },
                Flags = 0,
                ProviderKey = providerKey,
                Weight = 0,
            };
            var result = NativeMethods.FwpmSubLayerAdd0(engine, ref sublayer, IntPtr.Zero);
            if (result is not 0 and not FwpEAlreadyExists)
            {
                throw new Win32Exception((int)result);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(name);
            Marshal.FreeHGlobal(description);
            Marshal.FreeHGlobal(providerKey);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmDisplayData0
    {
        public IntPtr Name;
        public IntPtr Description;
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
        internal static partial void FwpmFreeMemory0(ref IntPtr p);
    }
}
