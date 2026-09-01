using System.Windows;
using System.Windows.Media;

namespace WinSight.Dashboard;

/// <summary>
/// Rebinds the shared surface brushes to the system palette when Windows is in high-contrast mode.
/// </summary>
/// <remarks>
/// <b>What was wrong.</b> The palette is seven hard-coded hex values, which is a reasonable way to
/// keep a card, a border and a button edge from drifting apart - and it means the dashboard renders
/// identically whatever the user has told Windows they need. Turning on high contrast, which is the
/// setting people with low vision actually use, changed nothing at all: the same mid-slate text on
/// the same white surface. A security tool nobody can read is a security tool nobody uses.
///
/// <b>Why the brushes are replaced rather than the styles rewritten.</b> Every control already
/// resolves its colours through these seven keys, so replacing the brushes reaches the whole UI,
/// including the second window, without touching a single style. The alternative - a parallel
/// high-contrast resource dictionary - is a second palette to keep in step with the first, which is
/// the drift the single palette exists to prevent.
///
/// <b>Severity is not carried by colour alone even now.</b> A finding's mark is a text label and an
/// icon before it is a colour, so a high-contrast palette does not have to encode severity - it has
/// to stop the text being unreadable, which is what this does.
///
/// It follows the setting live: Windows raises a change when the user toggles high contrast, and
/// the palette is applied again rather than requiring a restart.
/// </remarks>
public static class HighContrastPalette
{
    /// <summary>The brush keys the whole UI resolves its colours through.</summary>
    internal static readonly string[] Keys =
    [
        "AccentBrush", "AccentPressedBrush", "SurfaceBrush", "SurfaceEdgeBrush",
        "TextBrush", "DangerBrush", "SuccessBrush",
    ];

    private static ResourceDictionary? _designed;

    /// <summary>
    /// Applies the palette for the current setting, and keeps applying it as the setting changes.
    /// </summary>
    public static void Attach(System.Windows.Application application)
    {
        ArgumentNullException.ThrowIfNull(application);

        // The designed palette is captured on first use, before anything is replaced, so returning
        // from high contrast restores exactly what the product ships rather than an approximation.
        Apply(application.Resources, SystemParameters.HighContrast);
        SystemParameters.StaticPropertyChanged += (_, changed) =>
        {
            if (changed.PropertyName is null or nameof(SystemParameters.HighContrast))
            {
                application.Dispatcher.Invoke(
                    () => Apply(application.Resources, SystemParameters.HighContrast));
            }
        };
    }

    /// <summary>
    /// Swaps the palette in or out of a resource dictionary.
    /// </summary>
    /// <remarks>
    /// It takes the dictionary rather than the application because only one
    /// <see cref="System.Windows.Application"/> can exist per AppDomain, which would make this
    /// untestable - and an untested accessibility path is one nobody finds out is broken.
    /// </remarks>
    internal static void Apply(ResourceDictionary resources, bool highContrast)
    {
        ArgumentNullException.ThrowIfNull(resources);
        _designed ??= Capture(resources);

        foreach (var key in Keys)
        {
            resources[key] = highContrast ? SystemBrush(key) : _designed[key];
        }
    }

    /// <summary>Test seam: forgets the captured palette so each test starts from its own.</summary>
    internal static void Forget() => _designed = null;

    /// <summary>
    /// The system brush that carries the same meaning as one of the designed ones.
    /// </summary>
    /// <remarks>
    /// Every one of these is a live <see cref="System.Windows.SystemColors"/> brush rather than a copy, so the
    /// UI follows whichever high-contrast theme the user chose - there are four, and they do not
    /// agree about anything except that the designed palette is wrong for them.
    ///
    /// Danger and success have no system equivalent, because the high-contrast themes deliberately
    /// do not offer a spare accent. They resolve to the same text colour, which loses the colour
    /// distinction and keeps the contrast; the label and the icon still carry the meaning.
    /// </remarks>
    private static SolidColorBrush SystemBrush(string key) => key switch
    {
        "AccentBrush" => System.Windows.SystemColors.HighlightBrush,
        "AccentPressedBrush" => System.Windows.SystemColors.HotTrackBrush,
        "SurfaceBrush" => System.Windows.SystemColors.WindowBrush,
        "SurfaceEdgeBrush" => System.Windows.SystemColors.ActiveBorderBrush,
        _ => System.Windows.SystemColors.WindowTextBrush,
    };

    private static ResourceDictionary Capture(ResourceDictionary resources)
    {
        var designed = new ResourceDictionary();
        foreach (var key in Keys)
        {
            designed[key] = resources[key];
        }
        return designed;
    }
}
