using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace WinSight.Firewall;

/// <summary>
/// Stateless, domain-separated identity for a complete ordered IPC collection. The digest is
/// recomputed for every page so no caller can fill a privileged server-side snapshot cache.
/// Length prefixes make field boundaries unambiguous and the count binds the collection shape.
/// </summary>
internal static class FirewallSnapshotVersion
{
    private static readonly byte[] PolicyDomain = Encoding.UTF8.GetBytes("WinSight.Firewall/Snapshot/v1/policies");
    private static readonly byte[] PendingDomain = Encoding.UTF8.GetBytes("WinSight.Firewall/Snapshot/v1/pending");

    public static string ForPolicies(IReadOnlyList<AppFirewallPolicy> policies) =>
        Compute(PolicyDomain, policies.Count, hash =>
        {
            foreach (var policy in policies)
            {
                AddString(hash, policy.ExecutablePath);
                AddInt32(hash, (int)policy.Action);
                AddInt32(hash, policy.Enabled ? 1 : 0);
            }
        });

    public static string ForPending(IReadOnlyList<PendingOutboundApp> pending) =>
        Compute(PendingDomain, pending.Count, hash =>
        {
            foreach (var app in pending)
            {
                AddString(hash, app.ExecutablePath);
                AddString(hash, app.LastRemote);
                AddInt64(hash, app.FirstSeenUtc.UtcTicks);
                AddInt64(hash, app.FirstSeenUtc.Offset.Ticks);
                AddInt64(hash, app.LastSeenUtc.UtcTicks);
                AddInt64(hash, app.LastSeenUtc.Offset.Ticks);
                AddInt32(hash, app.Observations);
            }
        });

    private static string Compute(byte[] domain, int count, Action<IncrementalHash> append)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AddBytes(hash, domain);
        AddInt32(hash, count);
        append(hash);
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static void AddString(IncrementalHash hash, string value) =>
        AddBytes(hash, Encoding.UTF8.GetBytes(value));

    private static void AddBytes(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(length, value.Length);
        hash.AppendData(length);
        hash.AppendData(value);
    }

    private static void AddInt32(IncrementalHash hash, int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(bytes, value);
        hash.AppendData(bytes);
    }

    private static void AddInt64(IncrementalHash hash, long value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64LittleEndian(bytes, value);
        hash.AppendData(bytes);
    }
}
