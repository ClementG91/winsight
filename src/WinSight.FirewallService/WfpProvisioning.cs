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
/// They are the ownership scope under which WinSight audit and enforcement filters live.
///
/// Everything runs inside a WFP transaction so it is all-or-nothing. Production enforcement
/// creates these non-persistent objects through one service-owned dynamic session: BFE therefore
/// removes them when the service closes its session or dies, including an ungraceful crash. The
/// short-lived static entry points remain for read-only diagnostics and isolated native probes.
/// All mutation is idempotent (already-exists / not-found are treated as success).
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
    internal static readonly Guid AleAppIdCondition = new("d78e1e87-8644-4ea5-9437-d809ecefc971");

    // Two properties of this filter shape that the UI now states outright, because neither is
    // obvious and both change what an operator should expect:
    //
    //   Blocking is at ALE_AUTH_CONNECT only. Nothing is posted on ALE_FLOW_ESTABLISHED or
    //   ALE_ENDPOINT_CLOSURE, so blocking an application does not interrupt connections it already
    //   has open - the block takes effect at its next connect.
    //
    //   The only condition is ALE_APP_ID, with nothing on FLAG_IS_LOOPBACK, so the application's
    //   own local traffic is filtered too. That can break communication between components of one
    //   application, which is a surprising way for a "block outbound" rule to behave.
    //
    // Exempting loopback means a second filter condition (FWPM_CONDITION_FLAGS matched with
    // FWP_MATCH_FLAGS_NONE_SET against FWP_CONDITION_FLAG_IS_LOOPBACK) and a matching change to
    // the exact-inventory verification, which is the code that decides whether the machine reports
    // Active or Degraded. Neither can be exercised outside the VM campaign - creating WFP filters
    // on a development machine is forbidden by this project's own qualification rules - and getting
    // the verification subtly wrong would leave every machine reporting Degraded for ever. It is
    // deliberately left for a qualification run rather than shipped unverified; until then the
    // behaviour is stated where the operator decides.

    private const string ProviderName = "WinSight";
    private const string ProviderDescription = "WinSight-owned outbound firewall provider.";
    private const string SublayerName = "WinSight outbound";
    private const string SublayerDescription =
        "WinSight-owned outbound firewall filter sublayer.";

    private const string PermitFilterName = "WinSight audit permit";
    private const string PermitFilterDescription =
        "Non-blocking PERMIT filter (proves WFP filter interop; blocks nothing).";
    private const string BlockFilterName = "WinSight block";
    private const string BlockFilterDescription =
        "Blocks outbound connections for one application (per-app, IPv4 and IPv6).";

    /// <summary>
    /// Arbitration weight of the WinSight sublayer.
    /// </summary>
    /// <remarks>
    /// <b>It was 0, the minimum.</b> WFP arbitrates between sublayers by weight, and a filter in a
    /// heavier sublayer that carries <c>FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT</c> can veto a decision
    /// made in a lighter one. Sitting at the very bottom put WinSight's BLOCK below anything that
    /// cared to outrank it, on the one function of the product that actually stops traffic. There is
    /// no benefit to the minimum: a sublayer's weight does not affect what it matches, only who wins
    /// when two sublayers disagree.
    ///
    /// A high value rather than <c>0xFFFF</c>, which is conventionally left to the platform, and a
    /// deliberate choice not to attempt to outrank the Windows Firewall's own sublayer: WinSight
    /// blocks what the operator asked to block and has no business overruling the system firewall.
    ///
    /// BFE does not promise to preserve the requested value verbatim. Microsoft's provider sample
    /// uses <c>0x8000</c> specifically as a middle weight and documents that BFE assigns the closest
    /// available value. Native VM qualification observed the expected adjacent value
    /// <c>0x8001</c>. Exact-shape verification therefore accepts a bounded neighbourhood around the
    /// request while still rejecting the old floor weight and any materially different arbitration
    /// position.
    /// </remarks>
    private const ushort SublayerWeight = 0x8000;
    private const ushort SublayerWeightMaximumDrift = 0x1000;

    private const uint RpcCAuthnWinNt = 10;
    private const uint FwpmSessionFlagDynamic = 0x00000001;
    private const uint DynamicSessionTransactionWaitMilliseconds = 5_000;
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
    internal const uint FwpActionBlock = 0x00001001;
    private const uint FwpEmpty = 0;

    // FWP_DATA_TYPE.FWP_BYTE_BLOB_TYPE = 12 (10 is FWP_DOUBLE). The app-id condition
    // value is a byte blob, so this must be 12 or WFP rejects the condition.
    internal const uint FwpByteBlobType = 12;
    internal const uint FwpMatchEqual = 0;

    // FWPM_FILTER_FLAG_INDEXED = 0x40. WFP sets this itself, not the caller, on any filter it
    // decides to index for fast matching — which it always does for an app-id condition. A block
    // filter therefore reads back with Flags = 0x40, never 0. Confirmed on a live machine: the
    // filters apply and block correctly, yet a "Flags == 0" check would reject them, so the exact
    // check must mask this flag or it turns every real enforcement into a false "degraded".
    private const uint FwpmFilterFlagIndexed = 0x00000040;

    private const uint InventoryBatchSize = 256;
    private const int MaxInventoryFilters = 65_536;

    internal static uint ProductionSessionFlags => FwpmSessionFlagDynamic;
    internal static uint ProductionTransactionWaitMilliseconds => DynamicSessionTransactionWaitMilliseconds;

    /// <summary>Creates the provider and sublayer (idempotent). Installs no filter.</summary>
    public static void Provision()
    {
        var engine = OpenEngine();
        try
        {
            Provision(engine);
        }
        finally
        {
            _ = NativeMethods.FwpmEngineClose0(engine);
        }
    }

    internal static void Provision(IntPtr engine) =>
        InTransaction(engine, () =>
        {
            AddProvider(engine);
            AddSublayer(engine);
        });

    /// <summary>
    /// Opens the one session that owns production WFP policy. Objects created with this handle are
    /// tied to it by BFE and disappear on close or RPC rundown, so a dead service cannot leave a
    /// live block behind. A bounded transaction wait turns WFP contention into a visible degraded
    /// state instead of hanging the SYSTEM service indefinitely.
    /// </summary>
    internal static SafeWfpEngineSession OpenDynamicSession()
    {
        var session = new FwpmSession0
        {
            Flags = FwpmSessionFlagDynamic,
            TransactionWaitTimeoutMilliseconds = DynamicSessionTransactionWaitMilliseconds,
        };
        var sessionPointer = Marshal.AllocHGlobal(Marshal.SizeOf<FwpmSession0>());
        try
        {
            Marshal.StructureToPtr(session, sessionPointer, false);
            var result = NativeMethods.FwpmEngineOpen0(
                null, RpcCAuthnWinNt, IntPtr.Zero, sessionPointer, out var engine);
            if (result != 0)
            {
                throw new Win32Exception((int)result);
            }
            return new SafeWfpEngineSession(engine);
        }
        finally
        {
            Marshal.FreeHGlobal(sessionPointer);
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
        var engine = OpenEngine();
        try
        {
            AddBlockFilter(engine, executablePath);
        }
        finally
        {
            _ = NativeMethods.FwpmEngineClose0(engine);
        }
    }

    internal static void AddBlockFilter(IntPtr engine, string executablePath)
    {
        // Canonicalize once so the app id and the derived filter keys are computed from the
        // exact same path the store persists — otherwise a filter can be installed under a
        // key the next boot's re-apply cannot reproduce, orphaning it.
        var path = OutboundPolicyEvaluator.CanonicalPath(executablePath);
        var (keyV4, keyV6) = BlockFilterKeys(path);
        // Adding one application's block on request is the only place where an unusable path is a
        // caller error rather than a fact about a stored policy: the operator asked for this
        // specific application, so refusing loudly beats silently installing nothing.
        if (!TryGetAppIdBytes(path, out var appId))
        {
            throw new InvalidDataException(
                "The application path cannot be expressed as a Windows Filtering Platform application identifier.");
        }
        InTransaction(engine, () =>
        {
            // Replace only THIS app's filters, leaving other blocked apps intact.
            DeleteFilter(engine, keyV4);
            DeleteFilter(engine, keyV6);
            AddBlockFilters(engine, appId, keyV4, keyV6);
        });
    }

    /// <summary>
    /// Replaces the complete WinSight WFP namespace in one transaction. Inventory is
    /// obtained by enumerating the whole engine and selecting objects linked to either
    /// WinSight's provider or sublayer; policy-store paths are never used for cleanup.
    /// Only enabled block policies are recreated, at both outbound-connect layers.
    /// </summary>
    public static void ReconcileExact(IReadOnlyList<AppFirewallPolicy> policies)
    {
        ArgumentNullException.ThrowIfNull(policies);
        var engine = OpenEngine();
        try
        {
            ReconcileExact(engine, policies);
        }
        finally
        {
            _ = NativeMethods.FwpmEngineClose0(engine);
        }
    }

    internal static void ReconcileExact(IntPtr engine, IReadOnlyList<AppFirewallPolicy> policies)
    {
        ArgumentNullException.ThrowIfNull(policies);
        var desired = DesiredBlocks(policies);
        InTransaction(engine, () =>
        {
            // This also migrates objects left by pre-dynamic WinSight versions: static objects are
            // removed before the replacement provider, sublayer and filters are created in this
            // dynamic session, all in one atomic transaction.
            DeleteAllOwnedFilters(engine);
            DeleteSublayer(engine);
            DeleteProvider(engine);
            AddProvider(engine);
            AddSublayer(engine);
            foreach (var block in desired)
            {
                // A block whose path cannot be expressed as an application id is skipped, not
                // fatal. Failing the transaction here is what turned one unresolvable entry into a
                // rollback of the entire policy; VerifyExact applies the identical rule, so the
                // installed set and the expected set stay in exact agreement.
                if (TryGetAppIdBytes(block.Path, out var appId))
                {
                    AddBlockFilters(engine, appId, block.KeyV4, block.KeyV6);
                }
            }
        });
    }

    /// <summary>
    /// Reads the actual provider, sublayer and every filter, and accepts only the exact
    /// enabled-block set and shape produced by <see cref="ReconcileExact"/>. Missing,
    /// extra, malformed or unreadable native state fails closed.
    /// </summary>
    public static bool VerifyExact(IReadOnlyList<AppFirewallPolicy> policies)
    {
        ArgumentNullException.ThrowIfNull(policies);
        var desired = DesiredBlocks(policies);
        var expected = new Dictionary<Guid, ExpectedFilter>();
        foreach (var block in desired)
        {
            // Same rule as ReconcileExact, so "exact" keeps meaning exactly what was installable.
            // An inapplicable block expects no filter; if one is nevertheless present it becomes an
            // unexpected key below and verification fails closed, as it should.
            if (!TryGetAppIdBytes(block.Path, out var appId))
            {
                continue;
            }
            if (!expected.TryAdd(block.KeyV4, new ExpectedFilter(AleAuthConnectV4, appId))
                || !expected.TryAdd(block.KeyV6, new ExpectedFilter(AleAuthConnectV6, appId)))
            {
                return false;
            }
        }

        var engine = OpenEngine();
        try
        {
            if (!ProviderHasExactShape(engine) || !SublayerHasExactShape(engine))
            {
                return false;
            }

            var owned = EnumerateOwnedFilters(engine);
            if (owned.Count != expected.Count)
            {
                return false;
            }
            foreach (var filter in owned)
            {
                if (!expected.TryGetValue(filter.FilterKey, out var expectedFilter)
                    || !FilterHasExactShape(filter, expectedFilter))
                {
                    return false;
                }
            }
            return true;
        }
        finally
        {
            _ = NativeMethods.FwpmEngineClose0(engine);
        }
    }

    /// <summary>Removes every WinSight-owned filter and container in one transaction.</summary>
    public static void CleanupAll()
    {
        var engine = OpenEngine();
        try
        {
            CleanupAll(engine);
        }
        finally
        {
            _ = NativeMethods.FwpmEngineClose0(engine);
        }
    }

    internal static void CleanupAll(IntPtr engine) =>
        InTransaction(engine, () =>
        {
            DeleteAllOwnedFilters(engine);
            DeleteSublayer(engine);
            DeleteProvider(engine);
        });

    /// <summary>Removes one application's BLOCK filters from both IP layers (idempotent).</summary>
    public static void RemoveBlockFilter(string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        var engine = OpenEngine();
        try
        {
            RemoveBlockFilter(engine, executablePath);
        }
        finally
        {
            _ = NativeMethods.FwpmEngineClose0(engine);
        }
    }

    internal static void RemoveBlockFilter(IntPtr engine, string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        var (keyV4, keyV6) = BlockFilterKeys(executablePath);
        InTransaction(engine, () =>
        {
            DeleteFilter(engine, keyV4);
            DeleteFilter(engine, keyV6);
        });
    }

    /// <summary>True when the given application currently has a WinSight block filter.</summary>
    public static bool IsBlocked(string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        var (keyV4, keyV6) = BlockFilterKeys(executablePath);

        var engine = OpenEngine();
        try
        {
            return RequireConsistentIpPair(
                FilterExists(engine, keyV4),
                FilterExists(engine, keyV6),
                "application block");
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

    /// <summary>
    /// How many enabled blocks currently have no expressible application id, so an operator can be
    /// told what enforcement does not cover instead of it being silently absent.
    /// </summary>
    public static int InapplicableBlockCount(IReadOnlyList<AppFirewallPolicy> policies)
    {
        ArgumentNullException.ThrowIfNull(policies);
        var count = 0;
        foreach (var block in DesiredBlocks(policies))
        {
            if (!TryGetAppIdBytes(block.Path, out _))
            {
                count++;
            }
        }
        return count;
    }

    internal static List<DesiredBlock> DesiredBlocks(IReadOnlyList<AppFirewallPolicy> policies)
    {
        var result = new List<DesiredBlock>();
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var policy in policies)
        {
            ArgumentNullException.ThrowIfNull(policy);
            if (!policy.Enabled || policy.Action != OutboundAction.Block)
            {
                continue;
            }
            var path = OutboundPolicyEvaluator.CanonicalPath(policy.ExecutablePath);
            if (!paths.Add(path))
            {
                throw new InvalidDataException("The desired WFP policy set contains a duplicate path.");
            }
            var (keyV4, keyV6) = BlockFilterKeys(path);
            result.Add(new DesiredBlock(path, keyV4, keyV6));
        }
        return result;
    }

    /// <summary>
    /// Installs one application's BLOCK filters from an already-resolved application id.
    /// </summary>
    /// <remarks>
    /// The blob is built here from bytes rather than passing WFP's own allocation straight through,
    /// so the add path and <see cref="VerifyExact"/> consume one identical value. They used to call
    /// <c>FwpmGetAppIdFromFileName0</c> separately, which meant a file that vanished between the two
    /// produced a mismatch instead of a decision.
    /// </remarks>
    private static void AddBlockFilters(IntPtr engine, byte[] appId, Guid keyV4, Guid keyV6)
    {
        var dataPtr = Marshal.AllocHGlobal(appId.Length);
        var blobPtr = Marshal.AllocHGlobal(Marshal.SizeOf<FwpByteBlob>());
        var conditionPtr = Marshal.AllocHGlobal(Marshal.SizeOf<FwpmFilterCondition0>());
        try
        {
            Marshal.Copy(appId, 0, dataPtr, appId.Length);
            Marshal.StructureToPtr(
                new FwpByteBlob { Size = (uint)appId.Length, Data = dataPtr }, blobPtr, false);
            var condition = new FwpmFilterCondition0
            {
                FieldKey = AleAppIdCondition,
                MatchType = FwpMatchEqual,
                ConditionValue = new FwpConditionValue0 { Type = FwpByteBlobType, Value = blobPtr },
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
            Marshal.FreeHGlobal(blobPtr);
            Marshal.FreeHGlobal(dataPtr);
        }
    }

    /// <summary>
    /// The application id for a blocked path, or <see langword="false"/> when the path cannot be
    /// expressed as one at all.
    /// </summary>
    /// <remarks>
    /// <b>This used to throw, and the throw was the whole defect.</b>
    /// <c>FwpmGetAppIdFromFileName0</c> opens the target to learn its volume, so it fails whenever
    /// the binary is absent — deleted, on an unplugged volume, on an offline share. The resulting
    /// <see cref="Win32Exception"/> is classified by the coordinator as a failed transition, which
    /// rolls the entire policy back to audit-only, deletes every filter and returns the service to
    /// demand-start. One unresolvable entry disarmed the machine's whole outbound policy,
    /// persistently, and an attacker could cause it by deleting their own blocked binary.
    ///
    /// The id is a path, not a handle, so <see cref="WfpApplicationId"/> rebuilds the same bytes
    /// from the volume mapping and the filter outlives the file. Only a path with no volume at all
    /// — a UNC share, a mapped drive that is gone — yields false, and that entry is reported as
    /// inapplicable rather than taking the policy down with it.
    /// </remarks>
    internal static bool TryGetAppIdBytes(string path, out byte[] appId)
    {
        appId = [];
        var result = NativeMethods.FwpmGetAppIdFromFileName0(path, out var native);
        if (result == 0)
        {
            try
            {
                var blob = Marshal.PtrToStructure<FwpByteBlob>(native);
                if (blob.Size != 0 && blob.Data != IntPtr.Zero
                    && blob.Size <= WfpApplicationId.MaxAppIdBytes)
                {
                    var bytes = new byte[checked((int)blob.Size)];
                    Marshal.Copy(blob.Data, bytes, 0, bytes.Length);
                    appId = bytes;
                    return true;
                }
            }
            finally
            {
                NativeMethods.FwpmFreeMemory0(ref native);
            }
        }

        return WfpApplicationId.TryDerive(path, out appId);
    }
}
