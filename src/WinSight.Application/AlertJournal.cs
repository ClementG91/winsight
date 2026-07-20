using System.Globalization;

namespace WinSight.Application;

/// <summary>One recorded security detection: what fired, when, and on what.</summary>
/// <param name="TimeUtc">When it fired.</param>
/// <param name="Source">Which monitor raised it (e.g. Guardian, Ransomware).</param>
/// <param name="Kind">The signal, in the monitor's own vocabulary (e.g. CanaryTouched, RunKey).</param>
/// <param name="Detail">What it fired on — enough to act, without further lookup.</param>
public sealed record SecurityAlert(DateTimeOffset TimeUtc, string Source, string Kind, string Detail);

/// <summary>
/// A bounded, local-only journal of every security detection, written the moment one fires.
/// </summary>
/// <remarks>
/// <b>Why this exists.</b> A detection's only visible output used to be a tray balloon — and live
/// testing proved Windows can silently drop those: Focus Assist ("Ne pas déranger", including its
/// automatic full-screen rule) suppresses them outright, and the shell throttles an app that posts
/// several toasts in quick succession. Both look identical to "nothing was detected". A security tool
/// must not depend on a single output channel the OS is free to discard, so every detection is also
/// written here, where it survives a missed balloon, a suppressed one, and an app restart.
///
/// It follows the same discipline as <c>CrashReporter</c>: local-only (never sent anywhere), bounded
/// so it cannot grow without limit, and it never throws — journalling a detection must not become the
/// thing that breaks the monitor that detected it.
///
/// Unlike a balloon, this file is opened deliberately by its owner on their own machine, so it
/// records the full path rather than just the file name: a balloon can be shoulder-surfed or land in
/// a screenshot, whereas the journal is the place you go precisely because you need to know *which*
/// file was touched.
/// </remarks>
public static class AlertJournal
{
    /// <summary>Kept small; a journal is for recent history, not an archive.</summary>
    internal const int MaxEntries = 500;

    private const char Separator = '\t';

    /// <summary>The default local-only location: <c>%LocalAppData%\WinSight\alerts.log</c>.</summary>
    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WinSight",
        "alerts.log");

    /// <summary>Records a detection. Best-effort: never throws, whatever the target.</summary>
    public static void Append(SecurityAlert alert) => Append(alert, DefaultPath);

    /// <summary>
    /// Overload taking the target path so tests never write into the real <see cref="DefaultPath"/> —
    /// a test must not leave entries in the operator's own journal.
    /// </summary>
    internal static void Append(SecurityAlert alert, string path)
    {
        ArgumentNullException.ThrowIfNull(alert);
        try
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }
            File.AppendAllText(path, Format(alert) + Environment.NewLine);
            Trim(path);
        }
        // Deliberately broad: this runs on a detection path, so a malformed path or an unwritable
        // target must never turn a real alert into an exception that takes the monitor down.
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or ArgumentException
                                     or NotSupportedException)
        {
        }
    }

    /// <summary>The most recent entries, newest first. Empty when there is no readable journal.</summary>
    public static IReadOnlyList<SecurityAlert> Read(int max = 100) => Read(DefaultPath, max);

    internal static IReadOnlyList<SecurityAlert> Read(string path, int max)
    {
        if (max <= 0)
        {
            return [];
        }
        try
        {
            if (!File.Exists(path))
            {
                return [];
            }
            return File.ReadLines(path)
                .Select(Parse)
                .Where(alert => alert is not null)
                .Select(alert => alert!)
                .Reverse()
                .Take(max)
                .ToArray();
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or ArgumentException
                                     or NotSupportedException)
        {
            return [];
        }
    }

    /// <summary>One journal line. Pure, so the format is pinned by tests.</summary>
    internal static string Format(SecurityAlert alert)
    {
        ArgumentNullException.ThrowIfNull(alert);
        return string.Join(
            Separator,
            alert.TimeUtc.ToString("O", CultureInfo.InvariantCulture),
            Sanitize(alert.Source),
            Sanitize(alert.Kind),
            Sanitize(alert.Detail));
    }

    /// <summary>Parses one line, or null when it is not a well-formed entry.</summary>
    internal static SecurityAlert? Parse(string? line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return null;
        }
        var parts = line.Split(Separator);
        if (parts.Length != 4 ||
            !DateTimeOffset.TryParse(
                parts[0], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var time))
        {
            return null;
        }
        return new SecurityAlert(time, parts[1], parts[2], parts[3]);
    }

    // A tab or newline in a field would break the line format and make the entry unparseable, so
    // they become spaces. Losing exact whitespace matters far less than losing the whole record.
    private static string Sanitize(string? value) =>
        string.IsNullOrEmpty(value) ? string.Empty : value.Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');

    /// <summary>Keeps only the newest <see cref="MaxEntries"/> lines, so the journal stays bounded.</summary>
    private static void Trim(string path)
    {
        var lines = File.ReadAllLines(path);
        if (lines.Length <= MaxEntries)
        {
            return;
        }
        File.WriteAllLines(path, lines.Skip(lines.Length - MaxEntries));
    }
}
