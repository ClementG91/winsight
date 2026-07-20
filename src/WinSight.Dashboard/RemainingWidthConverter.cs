using System.Globalization;
using System.Windows.Data;

namespace WinSight.Dashboard;

/// <summary>
/// Reports how much of a container's width is left once a reserve is set aside for its other
/// content, for use as a sibling's <c>MaxWidth</c>.
/// </summary>
/// <remarks>
/// This exists to make a <c>WrapPanel</c> wrap only when it genuinely has to. A Grid measures an
/// <c>Auto</c> column with unlimited width, so a WrapPanel there reports the width of a single row
/// and is then arranged into whatever the column actually got — overflowing, and clipping its last
/// buttons off the window instead of wrapping. A constant cap fixes the clipping but forces the
/// wrap at every size, including wide windows where one row fits comfortably.
///
/// Expressing the cap as "the container minus the width the text needs" states the real rule:
/// the guidance stays readable, and the buttons keep one row for as long as what remains allows
/// one. It is deliberately not a percentage, which would only ever be a value tuned to today's
/// button labels in one language.
/// </remarks>
public sealed class RemainingWidthConverter : IValueConverter
{
    /// <summary>
    /// Below this the cap is ignored rather than honoured. A window narrow enough to leave less
    /// than one button's worth of room is better served by a row that overflows than by a cap of
    /// zero, which the layout system would honour by rendering no buttons at all.
    /// </summary>
    internal const double SmallestUsefulWidth = 120;

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not double width || double.IsNaN(width) || double.IsInfinity(width) || width <= 0)
        {
            // The first layout pass runs before the container has a width. No constraint leaves the
            // panel unwrapped for that one pass; a cap of zero would collapse it outright.
            return double.PositiveInfinity;
        }

        var remaining = width - ParseReserve(parameter);
        return remaining < SmallestUsefulWidth ? double.PositiveInfinity : remaining;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException("Layout widths are display-only and never flow back.");

    /// <summary>
    /// The reserve is authored in XAML rather than entered by the operator, so it parses as
    /// invariant: a machine whose culture uses a comma as the decimal separator must still read it
    /// the way it was written.
    /// </summary>
    private static double ParseReserve(object? parameter) => parameter switch
    {
        double reserve when reserve >= 0 => reserve,
        string text when double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed)
            && parsed >= 0 => parsed,
        _ => 0,
    };
}
