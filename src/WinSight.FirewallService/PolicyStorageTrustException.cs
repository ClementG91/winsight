namespace WinSight.FirewallService;

/// <summary>
/// The policy storage failed its trust inspection, carrying the deciding
/// <see cref="PathTrustCode"/> so callers can report which gate refused.
/// </summary>
/// <remarks>
/// The code travels as data rather than inside a message because the two callers need it and
/// neither may leak the rest: the service host writes it to the Windows event log, which the
/// VM protocol checks for path and SID disclosure, and the console prints it to an operator.
/// A <see cref="PathTrustCode"/> is an enum name — it says <em>which</em> rule refused without
/// saying which path or which principal tripped it. It derives from
/// <see cref="InvalidOperationException"/> so the existing catch filters still hold.
/// </remarks>
public sealed class PolicyStorageTrustException : InvalidOperationException
{
    public PolicyStorageTrustException(PathTrustCode code)
        : base($"Policy storage rejected [{code}].") => Code = code;

    public PolicyStorageTrustException(PathTrustCode code, Exception innerException)
        : base($"Policy storage rejected [{code}].", innerException) => Code = code;

    public PathTrustCode Code { get; }
}
