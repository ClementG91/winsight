namespace WinSight.Attribution;

/// <summary>Why a write could not be pinned on a process.</summary>
public enum UnattributedReason
{
    /// <summary>
    /// The writing process is not in the index: it was never announced, or its write reached us
    /// before its start event did.
    /// </summary>
    UnknownProcess,

    /// <summary>
    /// The key or file could not be resolved to a path anyone would recognise — an unannounced key
    /// handle, or a device with no drive letter.
    /// </summary>
    UnresolvedTarget,
}

/// <summary>A write that was observed but could not be attributed, and why.</summary>
/// <remarks>
/// Reported rather than discarded, deliberately. Dropping an unattributable write is the right
/// call — a wrong process name beside a security finding is worse than no name — but dropping it
/// <i>silently</i> is how a monitor comes to look healthy while seeing nothing, which this project
/// has now been bitten by twice: a signature verifier that swallowed its child's stderr, and this
/// watcher's own first version, which recorded nothing live and printed a reassuring burst anyway.
///
/// A tool that can say "I saw four hundred writes and could not attribute twelve" is one an
/// operator can calibrate. One that says nothing is indistinguishable from one that is broken.
/// </remarks>
/// <param name="WhenUtc">When the kernel reported the write.</param>
/// <param name="ProcessId">The process that performed it, which is all we know about it.</param>
/// <param name="Target">The target, when it resolved; null when that is what failed.</param>
/// <param name="Reason">Which half was missing.</param>
public sealed record UnattributedWrite(
    DateTimeOffset WhenUtc,
    int ProcessId,
    string? Target,
    UnattributedReason Reason);
