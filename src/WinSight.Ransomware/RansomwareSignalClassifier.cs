namespace WinSight.Ransomware;

/// <summary>
/// Maps a raw filesystem change to the ransomware signal it represents, if any. Pure and testable —
/// no I/O — so the watcher stays a thin shell over a decision that is unit-tested.
/// </summary>
public static class RansomwareSignalClassifier
{
    /// <summary>
    /// The signal a change represents, or null when it is not, on its own, suspicious. A change to a
    /// canary is always <see cref="RansomwareSignalKind.CanaryTouched"/> — a decoy has no legitimate
    /// reason to change. A rename or delete of an ordinary file is a burst signal; a create/change of
    /// an ordinary file is not a signal in this increment (entropy-on-write is deferred, because
    /// legitimately compressed files — .docx/.jpg/.zip — are high-entropy and would false-positive).
    /// </summary>
    public static RansomwareSignalKind? Classify(WatcherChangeTypes changeType, bool isCanary)
    {
        if (isCanary)
        {
            return RansomwareSignalKind.CanaryTouched;
        }

        return changeType switch
        {
            WatcherChangeTypes.Renamed => RansomwareSignalKind.Rename,
            WatcherChangeTypes.Deleted => RansomwareSignalKind.Delete,
            _ => null,
        };
    }
}
