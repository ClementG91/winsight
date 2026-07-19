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
    /// reason to change. A rename or delete of an ordinary file is a burst signal. A create/change is
    /// a signal only when the content <paramref name="looksEncrypted"/>, which the caller determines
    /// via <see cref="RansomwareEntropySampler"/> (it skips formats that are compressed by design, so
    /// saving a .docx or a .jpg never counts).
    /// </summary>
    public static RansomwareSignalKind? Classify(
        WatcherChangeTypes changeType, bool isCanary, bool looksEncrypted = false)
    {
        if (isCanary)
        {
            return RansomwareSignalKind.CanaryTouched;
        }

        return changeType switch
        {
            WatcherChangeTypes.Renamed => RansomwareSignalKind.Rename,
            WatcherChangeTypes.Deleted => RansomwareSignalKind.Delete,
            WatcherChangeTypes.Created or WatcherChangeTypes.Changed when looksEncrypted =>
                RansomwareSignalKind.HighEntropyWrite,
            _ => null,
        };
    }
}
