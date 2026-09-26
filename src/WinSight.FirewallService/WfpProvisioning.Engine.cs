using System.ComponentModel;
using System.Runtime.InteropServices;

namespace WinSight.FirewallService;

public static partial class WfpProvisioning
{
    internal sealed record DesiredBlock(string Path, Guid KeyV4, Guid KeyV6);
    internal sealed record ExpectedFilter(Guid LayerKey, byte[] AppId);
    internal sealed record FilterCondition(Guid FieldKey, uint MatchType, uint Type, byte[]? Value);
    internal sealed record OwnedFilter(
        Guid FilterKey,
        Guid? ProviderKey,
        Guid LayerKey,
        Guid SubLayerKey,
        uint Flags,
        uint ActionType,
        uint ConditionCount,
        FilterCondition? Condition);

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
            if (result == FwpEAlreadyExists)
            {
                // Not success. A filter already carrying this key is not necessarily the filter
                // being installed: it can hold different conditions or the opposite action - an old
                // PERMIT where a BLOCK is wanted. Accepting it meant the reconciler believed it had
                // installed what it asked for, and the verification, which enumerates by key, then
                // found a filter and agreed.
                //
                // Reconciliation is exact and deletes before it adds, so reaching this at all means
                // something survived that delete. Replacing it is what makes the installed filter
                // the intended one; this runs inside the provisioning transaction, so a failure
                // still aborts the whole change rather than leaving a hole.
                DeleteFilter(engine, filterKey);
                result = NativeMethods.FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out _);
            }
            if (result != 0)
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
            var providerResult = NativeMethods.FwpmProviderGetByKey0(
                engine, ref providerKey, out var provider);
            bool providerExists;
            try
            {
                providerExists = InterpretLookupResult(providerResult, FwpEProviderNotFound);
            }
            finally
            {
                if (provider != IntPtr.Zero)
                {
                    NativeMethods.FwpmFreeMemory0(ref provider);
                }
            }

            var sublayerKey = SublayerKey;
            var sublayerResult = NativeMethods.FwpmSubLayerGetByKey0(
                engine, ref sublayerKey, out var sublayer);
            bool sublayerExists;
            try
            {
                sublayerExists = InterpretLookupResult(sublayerResult, FwpESublayerNotFound);
            }
            finally
            {
                if (sublayer != IntPtr.Zero)
                {
                    NativeMethods.FwpmFreeMemory0(ref sublayer);
                }
            }

            // Transactions normally keep the pair in step, but diagnostics must report the
            // observed state rather than assuming it. A split pair is corruption, not "present"
            // or "absent", and must therefore fail the status command visibly.
            var permitExists = RequireConsistentIpPair(
                FilterExists(engine, PermitFilterKeyV4),
                FilterExists(engine, PermitFilterKeyV6),
                "audit permit filter");
            return (providerExists, sublayerExists, permitExists);
        }
        finally
        {
            _ = NativeMethods.FwpmEngineClose0(engine);
        }
    }

    private static bool FilterExists(IntPtr engine, Guid key)
    {
        var result = NativeMethods.FwpmFilterGetByKey0(engine, ref key, out var filter);
        try
        {
            return InterpretLookupResult(result, FwpEFilterNotFound);
        }
        finally
        {
            if (filter != IntPtr.Zero)
            {
                NativeMethods.FwpmFreeMemory0(ref filter);
            }
        }
    }

    internal static bool InterpretLookupResult(uint result, uint notFoundResult)
    {
        if (result == 0)
        {
            return true;
        }
        if (result == notFoundResult)
        {
            return false;
        }
        throw new Win32Exception(unchecked((int)result));
    }

    internal static bool RequireConsistentIpPair(bool ipv4, bool ipv6, string objectName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(objectName);
        if (ipv4 != ipv6)
        {
            throw new InvalidDataException(
                $"The WinSight WFP {objectName} has inconsistent IPv4/IPv6 state.");
        }
        return ipv4;
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
                Weight = SublayerWeight,
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
}
