using WinSight.Ransomware;

namespace WinSight.Application;

/// <summary>
/// UI-agnostic mapping of a ransomware detection to localization keys and display text, so the
/// dashboard's alert stays free of decision logic and is unit-tested without a UI. Mirrors
/// <see cref="PersistenceMonitorPresenter"/>.
/// </summary>
public static class RansomwarePresenter
{
    /// <summary>
    /// The localization key for the alert body. A touched canary is the high-confidence case — a
    /// decoy has no legitimate reason to change — and is worded more decisively than a burst, which
    /// is a heuristic and can (rarely) be ordinary bulk activity.
    /// </summary>
    public static string AlertMessageKey(RansomwareSignalKind kind) => kind switch
    {
        RansomwareSignalKind.CanaryTouched => "RansomwareCanaryTouched",
        _ => "RansomwareBurstDetected",
    };

    /// <summary>
    /// True when the detection warrants the loudest presentation. A touched decoy is as close to
    /// certain as this tool gets without a driver, so it is never presented as a mere warning.
    /// </summary>
    public static bool IsCritical(RansomwareSignalKind kind) =>
        kind == RansomwareSignalKind.CanaryTouched;

    /// <summary>
    /// A short, human line naming what tripped the detector, appended to the localized message. The
    /// file name alone is shown, not the full path, so an alert never leaks a directory tree into a
    /// screenshot or a balloon that may be shoulder-surfed.
    /// </summary>
    public static string Detail(RansomwareSignalKind kind, string? path)
    {
        var name = string.IsNullOrWhiteSpace(path) ? "(unknown)" : System.IO.Path.GetFileName(path);
        return string.IsNullOrWhiteSpace(name) ? kind.ToString() : $"{kind}: {name}";
    }
}
