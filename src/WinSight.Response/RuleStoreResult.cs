using System.Globalization;

namespace WinSight.Response;

/// <summary>Per-call rule-storage evidence; absence is distinct from an unreadable store.</summary>
public enum RuleStoreStatus
{
    Loaded, Missing, Written, TargetNotFound, InvalidRule, InvalidJson, InvalidFormat,
    UnsupportedVersion, ByteLimit, RuleLimit, Unavailable, WriteFailed,
}

public sealed record RuleStoreResult(RuleStoreStatus Status, int IgnoredEntries = 0)
{
    public bool Readable => Status is RuleStoreStatus.Loaded or RuleStoreStatus.Missing;
    public bool Durable => Status == RuleStoreStatus.Written;

    public string Detail => $"rule storage status: {Status}; " + (Status switch
    {
        RuleStoreStatus.InvalidJson or RuleStoreStatus.InvalidFormat => "the rule file is malformed and was preserved; inspect winsight rules and RECOVERY.md",
        RuleStoreStatus.UnsupportedVersion => "the rule-file version is unsupported and was preserved; use the compatible version or recover a reviewed backup",
        RuleStoreStatus.ByteLimit => "the 8 MiB rule-file budget was exceeded; the existing file was preserved",
        RuleStoreStatus.RuleLimit => "the 8192-entry rule-file budget was exceeded; revoke a rule from a readable store or recover a reviewed backup",
        RuleStoreStatus.Unavailable => "check ordinary local-file access, sharing and free disk space, then retry",
        RuleStoreStatus.WriteFailed => "atomic rule replacement failed; check disk space, permissions and conflicting file handles, then retry",
        RuleStoreStatus.InvalidRule => "a rule requires a nonempty identity, a key and supported scope, decision and duration; timed rules require an expiry",
        RuleStoreStatus.TargetNotFound => "the rule is absent from the readable store",
        _ => "inspect winsight rules for the stored decisions",
    }) + (IgnoredEntries == 0 ? string.Empty
        : $"; ignored entries: {IgnoredEntries.ToString(CultureInfo.InvariantCulture)}; "
            + (Durable ? "invalid entries were removed by this successful write" : "invalid entries remain intact until a successful write"));
}
