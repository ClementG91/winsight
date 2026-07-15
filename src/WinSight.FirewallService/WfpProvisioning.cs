using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using WinSight.Firewall;

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

    /// <summary>Stable identity of the WinSight non-blocking PERMIT audit filter (IPv4).</summary>
    public static readonly Guid PermitFilterKeyV4 = new("d7a9b1e2-5c3a-4b8e-9f21-6c0a7e2d1f34");

    /// <summary>Stable identity of the WinSight non-blocking PERMIT audit filter (IPv6).</summary>
    public static readonly Guid PermitFilterKeyV6 = new("d7a9b1e4-5c3a-4b8e-9f21-6c0a7e2d1f34");

    // The outbound-connect authorization layers. A real outbound firewall MUST cover both
    // IP versions: an app that reaches the network over IPv6 would otherwise bypass an
    // IPv4-only filter. Every filter below is installed at both.
    private static readonly Guid AleAuthConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    private static readonly Guid AleAuthConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");

    // FWPM_CONDITION_ALE_APP_ID: matches the connecting application's binary.
    private static readonly Guid AleAppIdCondition = new("d78e1e87-8644-4ea5-9437-d809ecefc971");

    private const string ProviderName = "WinSight";
    private const string ProviderDescription = "WinSight outbound firewall provider (audit-only).";
    private const string SublayerName = "WinSight outbound";
    private const string SublayerDescription =
        "WinSight outbound firewall sublayer (audit-only, no filter installed).";

    private const string PermitFilterName = "WinSight audit permit";
    private const string PermitFilterDescription =
        "Non-blocking PERMIT filter (proves WFP filter interop; blocks nothing).";
    private const string BlockFilterName = "WinSight block";
    private const string BlockFilterDescription =
        "Blocks outbound connections for one application (per-app, IPv4 and IPv6).";

    private const uint RpcCAuthnWinNt = 10;
    private const uint FwpEFilterNotFound = 0x80320003;
    private const uint FwpEProviderNotFound = 0x80320005;
    private const uint FwpESublayerNotFound = 0x80320007;
    private const uint FwpEAlreadyExists = 0x80320009;

    // FWP_ACTION_PERMIT = FWP_ACTION_FLAG_TERMINATING (0x1000) | 0x02. A PERMIT does not
    // block: it authorizes the connection, which is already the default, so adding it
    // changes no observable behaviour. FWP_EMPTY weight lets WFP auto-assign a weight.
    private const uint FwpActionPermit = 0x00001002;

    // FWP_ACTION_BLOCK = FWP_ACTION_FLAG_TERMINATING (0x1000) | 0x01. This one blocks,
    // but only the connections that match the filter's conditions (a single application).
    private const uint FwpActionBlock = 0x00001001;
    private const uint FwpEmpty = 0;

    // FWP_DATA_TYPE.FWP_BYTE_BLOB_TYPE = 12 (10 is FWP_DOUBLE). The app-id condition
    // value is a byte blob, so this must be 12 or WFP rejects the condition.
    private const uint FwpByteBlobType = 12;
    private const uint FwpMatchEqual = 0;

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

    /// <summary>
    /// Adds a single non-blocking PERMIT filter to the WinSight sublayer at the outbound
    /// connect layer. A PERMIT authorizes the connection (already the default), so this
    /// blocks nothing; it proves the filter interop works. Requires the sublayer to exist
    /// (run <see cref="Provision"/> first). Idempotent.
    /// </summary>
    public static void AddPermitFilter()
    {
        var engine = OpenEngine();
        try
        {
            InTransaction(engine, () =>
            {
                AddFilter(engine, PermitFilterKeyV4, AleAuthConnectV4, FwpActionPermit,
                    IntPtr.Zero, 0, PermitFilterName, PermitFilterDescription);
                AddFilter(engine, PermitFilterKeyV6, AleAuthConnectV6, FwpActionPermit,
                    IntPtr.Zero, 0, PermitFilterName, PermitFilterDescription);
            });
        }
        finally
        {
            _ = NativeMethods.FwpmEngineClose0(engine);
        }
    }

    /// <summary>Removes the PERMIT filter from both IP layers (idempotent).</summary>
    public static void RemovePermitFilter()
    {
        var engine = OpenEngine();
        try
        {
            DeleteFilter(engine, PermitFilterKeyV4);
            DeleteFilter(engine, PermitFilterKeyV6);
        }
        finally
        {
            _ = NativeMethods.FwpmEngineClose0(engine);
        }
    }

    /// <summary>
    /// Blocks outbound connections for one application, matched by its WFP app id (derived
    /// from the executable path). Only that binary is affected; every other application
    /// keeps connecting normally. The filter is installed at BOTH the IPv4 and IPv6 connect
    /// layers so the app cannot bypass it over IPv6. Multiple applications can be blocked at
    /// once, each keyed by a stable per-path GUID, so adding one never disturbs another.
    /// Idempotent per app, runs in one transaction, and requires the sublayer to exist
    /// (run <see cref="Provision"/> first).
    /// </summary>
    public static void AddBlockFilter(string executablePath)
    {
        // Canonicalize once so the app id and the derived filter keys are computed from the
        // exact same path the store persists — otherwise a filter can be installed under a
        // key the next boot's re-apply cannot reproduce, orphaning it.
        var path = OutboundPolicyEvaluator.CanonicalPath(executablePath);
        var (keyV4, keyV6) = BlockFilterKeys(path);

        var appId = GetAppId(path);
        try
        {
            var engine = OpenEngine();
            try
            {
                InTransaction(engine, () =>
                {
                    // Replace only THIS app's filters, leaving other blocked apps intact.
                    DeleteFilter(engine, keyV4);
                    DeleteFilter(engine, keyV6);

                    var conditionPtr = Marshal.AllocHGlobal(Marshal.SizeOf<FwpmFilterCondition0>());
                    try
                    {
                        var condition = new FwpmFilterCondition0
                        {
                            FieldKey = AleAppIdCondition,
                            MatchType = FwpMatchEqual,
                            ConditionValue = new FwpConditionValue0 { Type = FwpByteBlobType, Value = appId },
                        };
                        Marshal.StructureToPtr(condition, conditionPtr, false);

                        AddFilter(engine, keyV4, AleAuthConnectV4, FwpActionBlock,
                            conditionPtr, 1, BlockFilterName, BlockFilterDescription);
                        AddFilter(engine, keyV6, AleAuthConnectV6, FwpActionBlock,
                            conditionPtr, 1, BlockFilterName, BlockFilterDescription);
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(conditionPtr);
                    }
                });
            }
            finally
            {
                _ = NativeMethods.FwpmEngineClose0(engine);
            }
        }
        finally
        {
            NativeMethods.FwpmFreeMemory0(ref appId);
        }
    }

    /// <summary>Removes one application's BLOCK filters from both IP layers (idempotent).</summary>
    public static void RemoveBlockFilter(string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        var (keyV4, keyV6) = BlockFilterKeys(executablePath);

        var engine = OpenEngine();
        try
        {
            DeleteFilter(engine, keyV4);
            DeleteFilter(engine, keyV6);
        }
        finally
        {
            _ = NativeMethods.FwpmEngineClose0(engine);
        }
    }

    /// <summary>True when the given application currently has a WinSight block filter.</summary>
    public static bool IsBlocked(string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        var (keyV4, _) = BlockFilterKeys(executablePath);

        var engine = OpenEngine();
        try
        {
            return FilterExists(engine, keyV4);
        }
        finally
        {
            _ = NativeMethods.FwpmEngineClose0(engine);
        }
    }

    /// <summary>
    /// Deterministic, per-application filter keys (IPv4 and IPv6) derived from the
    /// canonical executable path. Stable across runs so a block can be found and removed,
    /// and distinct per app so blocking one never collides with another.
    /// </summary>
    public static (Guid V4, Guid V6) BlockFilterKeys(string executablePath)
    {
        // Same canonical form as the policy store (quote-stripped, absolute, normalized),
        // then lower-cased because Windows paths are case-insensitive, so a query and the
        // stored policy always derive the same key.
        var seed = OutboundPolicyEvaluator.CanonicalPath(executablePath).ToLowerInvariant();
        return (DeriveGuid("winsight-block-v4|" + seed), DeriveGuid("winsight-block-v6|" + seed));
    }

    private static Guid DeriveGuid(string seed)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(seed));
        return new Guid(hash.AsSpan(0, 16));
    }

    // Adds one filter to one layer. Conditions (if any) are supplied pre-marshalled by the
    // caller so the same app-id blob can back both the IPv4 and IPv6 filters.
    private static void AddFilter(
        IntPtr engine, Guid filterKey, Guid layerKey, uint action,
        IntPtr conditions, uint conditionCount, string name, string description)
    {
        var namePtr = Marshal.StringToHGlobalUni(name);
        var descriptionPtr = Marshal.StringToHGlobalUni(description);
        var providerKey = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
        try
        {
            Marshal.StructureToPtr(ProviderKey, providerKey, false);
            var filter = new FwpmFilter0
            {
                FilterKey = filterKey,
                DisplayData = new FwpmDisplayData0 { Name = namePtr, Description = descriptionPtr },
                Flags = 0,
                ProviderKey = providerKey,
                LayerKey = layerKey,
                SubLayerKey = SublayerKey,
                Weight = new FwpValue0 { Type = FwpEmpty, Value = 0 },
                NumFilterConditions = conditionCount,
                FilterCondition = conditions,
                Action = new FwpmAction0 { Type = action, FilterOrCalloutKey = Guid.Empty },
            };
            var result = NativeMethods.FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out _);
            if (result is not 0 and not FwpEAlreadyExists)
            {
                throw new Win32Exception((int)result);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(namePtr);
            Marshal.FreeHGlobal(descriptionPtr);
            Marshal.FreeHGlobal(providerKey);
        }
    }

    private static void DeleteFilter(IntPtr engine, Guid filterKey)
    {
        var result = NativeMethods.FwpmFilterDeleteByKey0(engine, ref filterKey);
        if (result is not 0 and not FwpEFilterNotFound)
        {
            throw new Win32Exception((int)result);
        }
    }

    private static IntPtr GetAppId(string executablePath)
    {
        var result = NativeMethods.FwpmGetAppIdFromFileName0(executablePath, out var appId);
        if (result != 0)
        {
            throw new Win32Exception((int)result);
        }
        return appId;
    }

    /// <summary>
    /// Reports the WinSight WFP containers and the audit PERMIT filter. Per-application
    /// block filters are keyed by path (many can coexist); use <see cref="IsBlocked"/> to
    /// query a specific application.
    /// </summary>
    public static (bool Provider, bool Sublayer, bool PermitFilter) Status()
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

            // The PERMIT filter is "present" when its IPv4 half exists; the V6 half is added
            // and removed in the same transaction, so the two are always in step.
            return (providerExists, sublayerExists, FilterExists(engine, PermitFilterKeyV4));
        }
        finally
        {
            _ = NativeMethods.FwpmEngineClose0(engine);
        }
    }

    private static bool FilterExists(IntPtr engine, Guid key)
    {
        var exists = NativeMethods.FwpmFilterGetByKey0(engine, ref key, out var filter) == 0;
        if (filter != IntPtr.Zero)
        {
            NativeMethods.FwpmFreeMemory0(ref filter);
        }
        return exists;
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

        [LibraryImport("fwpuclnt.dll", StringMarshalling = StringMarshalling.Utf16)]
        internal static partial uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);

        [LibraryImport("fwpuclnt.dll")]
        internal static partial void FwpmFreeMemory0(ref IntPtr p);
    }
}
