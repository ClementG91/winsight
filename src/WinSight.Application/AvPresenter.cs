using WinSight.AvMonitor;

namespace WinSight.Application;

/// <summary>
/// Turns a capture-device usage into the short name a balloon should show.
/// </summary>
public static class AvPresenter
{
    /// <summary>
    /// The app as an operator should read it in an alert: the executable's name, not its path.
    /// </summary>
    /// <remarks>
    /// Same reasoning as the ransomware balloon, and found the same way — by looking at a real
    /// alert. A desktop app is recorded by full path, and showing that verbatim produced a balloon
    /// four wrapped lines long, truncated before the part that identifies anything. It also put the
    /// operator's folder layout on screen, which a balloon can leak to a shoulder-surfer or a
    /// screenshot for no benefit: the file name is what answers "what is using my microphone".
    /// The journal keeps the full path, because that is opened deliberately to investigate.
    ///
    /// Packaged apps are recorded by package family name rather than a path, so they are shown
    /// as-is — trimming one at a separator would mangle an identifier that has no directories in it.
    /// </remarks>
    public static string DisplayName(DeviceUsage usage)
    {
        ArgumentNullException.ThrowIfNull(usage);
        if (string.IsNullOrWhiteSpace(usage.App))
        {
            return "(unknown)";
        }
        if (usage.Packaged)
        {
            return usage.App;
        }
        var name = Path.GetFileName(usage.App.TrimEnd('\\', '/'));
        return string.IsNullOrWhiteSpace(name) ? usage.App : name;
    }
}
