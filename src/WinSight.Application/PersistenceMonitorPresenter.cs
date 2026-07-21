using WinSight.Attribution;
using WinSight.Persistence;

namespace WinSight.Application;

/// <summary>
/// UI-agnostic rendering of a live persistence detection (Guardian) into the sentence an operator
/// reads and the localization key the tray balloon uses. Kept out of WPF so both are unit-tested
/// without a UI.
/// </summary>
/// <remarks>
/// This once also built a parallel <c>persistence-live</c> report of the current session's arrivals.
/// Nothing ever rendered it: Guardian's detections reach the operator through the alert journal,
/// which does the same job and survives a restart and a suppressed balloon — the failure modes the
/// journal was built for in the first place. A second, unreachable rendering path in a security tool
/// is worse than no second path, because it drifts from the live one while still looking tested, so
/// it was removed rather than wired up, and the one thing it showed that the journal did not — the
/// signature verdict — moved into the journal line below.
/// </remarks>
public static class PersistenceMonitorPresenter
{
    /// <summary>
    /// The journal line for a detection: what arrived, where it points, whether it is signed, and —
    /// when attribution was watching and can say — which program put it there.
    /// </summary>
    /// <remarks>
    /// Lives here rather than in the dashboard because it is the one sentence an operator reads when
    /// they come back to a machine that alerted while they were away, and a sentence that important
    /// should be pinned by tests instead of assembled inline in a WPF event handler.
    ///
    /// The journal records the full executable path, not just the file name shown in the balloon: it
    /// is opened deliberately, on one's own machine, precisely because one needs to know exactly
    /// which program to look at.
    /// </remarks>
    public static string AlertDetail(
        PersistenceEvent detection,
        Func<string?, DateTimeOffset, WriteObservation?>? attribute = null)
    {
        ArgumentNullException.ThrowIfNull(detection);
        var entry = detection.Entry;
        var target = entry.ImagePath ?? entry.ExpectedImagePath ?? entry.Command;
        var line = $"{entry.Name} — {target} [{StatusLabel(entry.Status)}]";
        var author = attribute?.Invoke(entry.Location, detection.FirstSeenUtc);
        if (author is null)
        {
            return line;
        }
        // A bare-name launch is named, but never dressed up as a located file: "powershell.exe" and
        // "C:\Windows\...\powershell.exe" mean different things to someone deciding what to do next.
        var by = author.PathIsExact
            ? $"{author.ExecutablePath} (pid {author.ProcessId})"
            : $"{author.ExecutablePath} (pid {author.ProcessId}, full path unknown)";
        return $"{line} — written by {by}";
    }

    /// <summary>
    /// The localization key for the tray balloon shown when a new entry is detected. A notable
    /// arrival (unsigned / untrusted / missing) is loud; a signed-trusted arrival is calm.
    /// </summary>
    public static string BalloonMessageKey(PersistenceEvent detection)
    {
        ArgumentNullException.ThrowIfNull(detection);
        return detection.IsNotable ? "GuardianDetectedNotable" : "GuardianDetectedSigned";
    }

    private static string StatusLabel(PersistenceStatus status) => status switch
    {
        PersistenceStatus.FileMissing => "file missing, signature not checked",
        PersistenceStatus.SignatureValid => "signature valid",
        PersistenceStatus.Unsigned => "unsigned",
        PersistenceStatus.InvalidSignature => "invalid signature",
        PersistenceStatus.AccessDenied => "access denied, signature not checked",
        _ => "verification error",
    };
}
