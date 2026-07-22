using WinSight.Attribution;
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

    /// <summary>
    /// The journal line for a ransomware detection: what tripped it, and — when attribution was
    /// watching and can say — which program did it.
    /// </summary>
    /// <remarks>
    /// <b>Why the journal carries the full path and the author, and the balloon does not.</b> The
    /// balloon may be read over someone's shoulder, so it shows a file name only. The journal is
    /// opened deliberately, on one's own machine, by someone who has just been told their files are
    /// being encrypted and needs to know what to kill. "CanaryTouched: decoy.docx" tells them
    /// something is wrong; "written by C:\Users\me\AppData\Local\Temp\x.exe (pid 8121)" tells them
    /// what to do about it. That difference is the entire reason attribution exists.
    ///
    /// A rename/delete burst normally arrives without an author, and that is by design rather than a
    /// failure: attributing it would mean recording every write in the user's document folders, which
    /// floods the correlation index and destroys the answers it exists to give. A touched decoy — the
    /// high-confidence signal — is the one that carries a name.
    /// </remarks>
    public static string AlertDetail(
        RansomwareSignalKind kind,
        string? path,
        Func<string?, DateTimeOffset, WriteObservation?>? attribute = null,
        DateTimeOffset? detectedAtUtc = null)
    {
        var line = string.IsNullOrWhiteSpace(path)
            ? kind.ToString()
            : $"{kind}: {path}";
        var author = attribute?.Invoke(path, detectedAtUtc ?? DateTimeOffset.UtcNow);
        if (author is null)
        {
            return line;
        }
        // A bare-name launch is named, never dressed up as a located file: an operator deciding what
        // to terminate must be able to tell "powershell.exe" from a path they can go and inspect.
        var by = author.PathIsExact
            ? $"{author.ExecutablePath} (pid {author.ProcessId})"
            : $"{author.ExecutablePath} (pid {author.ProcessId}, full path unknown)";
        return $"{line} — written by {by}";
    }
}
