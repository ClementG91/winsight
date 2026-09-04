using System.Globalization;
using System.Text;

namespace WinSight.Reporting;

/// <summary>
/// Makes machine-controlled text safe to place in a terminal or a visual security report.
/// The evidence itself remains unchanged in the JSON contract and report model.
/// </summary>
public static class UntrustedDisplayText
{
    private const string TruncatedMarker = "…[truncated]";

    /// <summary>
    /// Escapes terminal controls, line-breaking controls and invisible Unicode formatting marks.
    /// </summary>
    public static string Neutralize(string? value, int maxLength = 4096)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxLength, TruncatedMarker.Length);

        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var result = new StringBuilder(Math.Min(value.Length, maxLength));
        var boundaries = new List<int>();
        foreach (var rune in value.EnumerateRunes())
        {
            var replacement = Escape(rune);
            if (result.Length + replacement.Length > maxLength)
            {
                while (result.Length + TruncatedMarker.Length > maxLength
                       && boundaries.Count > 0)
                {
                    result.Length = boundaries[^1];
                    boundaries.RemoveAt(boundaries.Count - 1);
                }
                result.Append(TruncatedMarker);
                break;
            }
            boundaries.Add(result.Length);
            result.Append(replacement);
        }

        return result.ToString();
    }

    private static string Escape(Rune rune)
    {
        return rune.Value switch
        {
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            _ when IsInvisibleOrControl(rune) => rune.IsBmp
                ? $"\\u{rune.Value:X4}"
                : $"\\U{rune.Value:X8}",
            _ => rune.ToString(),
        };
    }

    private static bool IsInvisibleOrControl(Rune rune)
    {
        var category = Rune.GetUnicodeCategory(rune);
        return category is UnicodeCategory.Control
            or UnicodeCategory.Format
            or UnicodeCategory.LineSeparator
            or UnicodeCategory.ParagraphSeparator;
    }
}
