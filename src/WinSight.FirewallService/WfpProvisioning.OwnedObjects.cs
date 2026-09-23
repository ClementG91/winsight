using System.ComponentModel;
using System.Runtime.InteropServices;
using WinSight.Firewall;

namespace WinSight.FirewallService;

public static partial class WfpProvisioning
{
    private static bool ProviderHasExactShape(IntPtr engine)
    {
        var key = ProviderKey;
        var result = NativeMethods.FwpmProviderGetByKey0(engine, ref key, out var pointer);
        if (result == FwpEProviderNotFound)
        {
            return false;
        }
        if (result != 0)
        {
            throw new Win32Exception((int)result);
        }
        try
        {
            var provider = Marshal.PtrToStructure<FwpmProvider0>(pointer);
            return provider.ProviderKey == ProviderKey && provider.Flags == 0;
        }
        finally
        {
            NativeMethods.FwpmFreeMemory0(ref pointer);
        }
    }

    private static bool SublayerHasExactShape(IntPtr engine)
    {
        var key = SublayerKey;
        var result = NativeMethods.FwpmSubLayerGetByKey0(engine, ref key, out var pointer);
        if (result == FwpESublayerNotFound)
        {
            return false;
        }
        if (result != 0)
        {
            throw new Win32Exception((int)result);
        }
        try
        {
            var sublayer = Marshal.PtrToStructure<FwpmSublayer0>(pointer);
            return sublayer.SubLayerKey == SublayerKey
                && sublayer.Flags == 0
                // BFE assigns the closest available value rather than guaranteeing the requested
                // weight verbatim. Keep the meaningful arbitration band exact enough to rebuild an
                // old floor-weight sublayer without rejecting a healthy BFE-adjusted value.
                && SublayerWeightIsAcceptable(sublayer.Weight)
                && sublayer.ProviderKey != IntPtr.Zero
                && Marshal.PtrToStructure<Guid>(sublayer.ProviderKey) == ProviderKey;
        }
        finally
        {
            NativeMethods.FwpmFreeMemory0(ref pointer);
        }
    }

    private static List<OwnedFilter> EnumerateOwnedFilters(IntPtr engine)
    {
        var create = NativeMethods.FwpmFilterCreateEnumHandle0(engine, IntPtr.Zero, out var enumHandle);
        if (create != 0)
        {
            throw new Win32Exception((int)create);
        }

        var result = new List<OwnedFilter>();
        var enumerated = 0;
        try
        {
            while (true)
            {
                var enumerate = NativeMethods.FwpmFilterEnum0(
                    engine, enumHandle, InventoryBatchSize, out var entries, out var count);
                if (enumerate != 0)
                {
                    throw new Win32Exception((int)enumerate);
                }
                try
                {
                    enumerated = checked(enumerated + checked((int)count));
                    if (enumerated > MaxInventoryFilters)
                    {
                        throw new InvalidDataException("The WFP inventory exceeds its safety bound.");
                    }
                    for (uint index = 0; index < count; index++)
                    {
                        var filterPointer = Marshal.ReadIntPtr(entries, checked((int)index * IntPtr.Size));
                        if (filterPointer == IntPtr.Zero)
                        {
                            throw new InvalidDataException("WFP returned an invalid filter inventory entry.");
                        }
                        var filter = Marshal.PtrToStructure<FwpmFilter0>(filterPointer);
                        var providerKey = filter.ProviderKey == IntPtr.Zero
                            ? (Guid?)null
                            : Marshal.PtrToStructure<Guid>(filter.ProviderKey);
                        if (providerKey == ProviderKey || filter.SubLayerKey == SublayerKey)
                        {
                            result.Add(CopyOwnedFilter(filter, providerKey));
                        }
                    }
                }
                finally
                {
                    if (entries != IntPtr.Zero)
                    {
                        NativeMethods.FwpmFreeMemory0(ref entries);
                    }
                }
                if (count == 0)
                {
                    break;
                }
            }
        }
        catch
        {
            _ = NativeMethods.FwpmFilterDestroyEnumHandle0(engine, enumHandle);
            throw;
        }
        var destroy = NativeMethods.FwpmFilterDestroyEnumHandle0(engine, enumHandle);
        if (destroy != 0)
        {
            throw new Win32Exception((int)destroy);
        }
        return result;
    }

    private static OwnedFilter CopyOwnedFilter(FwpmFilter0 filter, Guid? providerKey)
    {
        FilterCondition? condition = null;
        if (filter.NumFilterConditions == 1 && filter.FilterCondition != IntPtr.Zero)
        {
            var native = Marshal.PtrToStructure<FwpmFilterCondition0>(filter.FilterCondition);
            byte[]? value = null;
            if (native.ConditionValue.Type == FwpByteBlobType && native.ConditionValue.Value != IntPtr.Zero)
            {
                var blob = Marshal.PtrToStructure<FwpByteBlob>(native.ConditionValue.Value);
                if (blob.Size > 0 && blob.Data != IntPtr.Zero
                    && blob.Size <= FirewallProtocolCodec.MaxPathUtf8BytesPerMessage)
                {
                    value = new byte[checked((int)blob.Size)];
                    Marshal.Copy(blob.Data, value, 0, value.Length);
                }
            }
            condition = new FilterCondition(
                native.FieldKey, native.MatchType, native.ConditionValue.Type, value);
        }
        return new OwnedFilter(
            filter.FilterKey, providerKey, filter.LayerKey, filter.SubLayerKey,
            filter.Flags, filter.Action.Type, filter.NumFilterConditions, condition);
    }

    internal static bool FilterHasExactShape(OwnedFilter filter, ExpectedFilter expected) =>
        filter.ProviderKey == ProviderKey
        && filter.SubLayerKey == SublayerKey
        && filter.LayerKey == expected.LayerKey
        && FilterFlagsAreClean(filter.Flags)
        && filter.ActionType == FwpActionBlock
        && filter.ConditionCount == 1
        && filter.Condition is { } condition
        && condition.FieldKey == AleAppIdCondition
        && condition.MatchType == FwpMatchEqual
        && condition.Type == FwpByteBlobType
        && condition.Value is not null
        && condition.Value.AsSpan().SequenceEqual(expected.AppId);

    /// <summary>
    /// True when a filter carries no flag WinSight did not intend. The INDEXED flag is masked out
    /// because WFP sets it itself on any app-id filter, so a real, correctly-applied block reads
    /// back with it; requiring Flags == 0 rejected every genuine enforcement and reported it as a
    /// false "degraded", confirmed on a live machine. Every other flag — PERSISTENT, BOOTTIME,
    /// DISABLED — stays disqualifying, since WinSight never creates such a filter.
    /// </summary>
    internal static bool FilterFlagsAreClean(uint flags) => (flags & ~FwpmFilterFlagIndexed) == 0;

    /// <summary>
    /// True when BFE kept the sublayer in the intended middle-high arbitration band. The bounded
    /// drift accommodates its documented closest-available assignment while 4,096 occupied
    /// neighbouring weights would already be an abnormal state worth rebuilding and reporting.
    /// </summary>
    internal static bool SublayerWeightIsAcceptable(ushort actualWeight) =>
        Math.Abs((int)actualWeight - SublayerWeight) <= SublayerWeightMaximumDrift;

    private static void DeleteAllOwnedFilters(IntPtr engine)
    {
        foreach (var filter in EnumerateOwnedFilters(engine))
        {
            var key = filter.FilterKey;
            DeleteFilter(engine, key);
        }
    }

    private static void DeleteSublayer(IntPtr engine)
    {
        var key = SublayerKey;
        var result = NativeMethods.FwpmSubLayerDeleteByKey0(engine, ref key);
        if (result is not 0 and not FwpESublayerNotFound)
        {
            throw new Win32Exception((int)result);
        }
    }

    private static void DeleteProvider(IntPtr engine)
    {
        var key = ProviderKey;
        var result = NativeMethods.FwpmProviderDeleteByKey0(engine, ref key);
        if (result is not 0 and not FwpEProviderNotFound)
        {
            throw new Win32Exception((int)result);
        }
    }
}
