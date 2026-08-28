using System.Globalization;

namespace WinSight.Application;

/// <summary>One recorded security detection: what fired, when, and on what.</summary>
/// <param name="TimeUtc">When it fired.</param>
/// <param name="Source">Which monitor raised it (e.g. Guardian, Ransomware).</param>
/// <param name="Kind">The signal, in the monitor's own vocabulary (e.g. CanaryTouched, RunKey).</param>
/// <param name="Detail">What it fired on — enough to act, without further lookup.</param>
public sealed record SecurityAlert(DateTimeOffset TimeUtc, string Source, string Kind, string Detail);

/// <summary>A journal read plus corruption/availability information.</summary>
public sealed record AlertJournalSnapshot(
    IReadOnlyList<SecurityAlert> Entries,
    bool Unreadable,
    int MalformedEntries);

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
    /// <summary>
    /// Lines currently in each journal, tracked so the bound can be enforced without reading the
    /// file on every append. Guarded by <c>Gate</c>, and bounded because a process writes to one
    /// journal (tests add one entry per temporary path).
    /// </summary>
    private static readonly Dictionary<string, int> LineCounts =
        new(StringComparer.OrdinalIgnoreCase);

    internal const int MaxEntries = 500;

    internal const int MaxFieldCharacters = 4096;

    private const long MaximumJournalBytes = 16 * 1024 * 1024;

    private const char Separator = '\t';
    private static readonly Lock Gate = new();

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
            lock (Gate)
            {
                var directory = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(directory))
                {
                    Directory.CreateDirectory(directory);
                }
                PreserveOversizedJournal(path);
                var payload = System.Text.Encoding.UTF8.GetBytes(Format(alert) + Environment.NewLine);
                using (var stream = new FileStream(
                           path,
                           FileMode.Append,
                           FileAccess.Write,
                           FileShare.Read,
                           bufferSize: 4096,
                           FileOptions.WriteThrough))
                {
                    stream.Write(payload);
                    stream.Flush(flushToDisk: true);
                }
                if (LineCounts.TryGetValue(path, out var known))
                {
                    LineCounts[path] = known + 1;
                }
                Trim(path);
            }
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
    public static IReadOnlyList<SecurityAlert> Read(int max = 100) =>
        ReadWithCoverage(DefaultPath, max).Entries;

    internal static IReadOnlyList<SecurityAlert> Read(string path, int max) =>
        ReadWithCoverage(path, max).Entries;

    internal static AlertJournalSnapshot ReadWithCoverage(string path, int max)
    {
        if (max <= 0)
        {
            return new AlertJournalSnapshot([], Unreadable: false, MalformedEntries: 0);
        }
        try
        {
            lock (Gate)
            {
                if (!File.Exists(path))
                {
                    return new AlertJournalSnapshot([], Unreadable: false, MalformedEntries: 0);
                }
                if (new FileInfo(path).Length > MaximumJournalBytes)
                {
                    return new AlertJournalSnapshot([], Unreadable: true, MalformedEntries: 0);
                }
                var malformed = 0;
                var entries = new List<SecurityAlert>();
                foreach (var line in File.ReadLines(path))
                {
                    if (Parse(line) is { } alert)
                    {
                        entries.Add(alert);
                    }
                    else
                    {
                        malformed++;
                    }
                }
                return new AlertJournalSnapshot(
                    entries.AsEnumerable().Reverse().Take(max).ToArray(),
                    Unreadable: false,
                    malformed);
            }
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or ArgumentException
                                     or NotSupportedException)
        {
            return new AlertJournalSnapshot([], Unreadable: true, MalformedEntries: 0);
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
            parts.Skip(1).Any(part => part.Length > MaxFieldCharacters) ||
            !DateTimeOffset.TryParse(
                parts[0], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var time))
        {
            return null;
        }
        return new SecurityAlert(time, parts[1], parts[2], parts[3]);
    }

    // A tab or newline in a field would break the line format and make the entry unparseable, so
    // they become spaces. Losing exact whitespace matters far less than losing the whole record.
    private static string Sanitize(string? value)
    {
        var sanitized = string.IsNullOrEmpty(value)
            ? string.Empty
            : value.Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');
        return sanitized.Length <= MaxFieldCharacters
            ? sanitized
            : sanitized[..(MaxFieldCharacters - 12)] + " [truncated]";
    }

    /// <summary>Keeps only the newest <see cref="MaxEntries"/> lines, so the journal stays bounded.</summary>
    /// <remarks>
    /// <b>The file is not re-read on every append.</b> This runs on the detection path - an
    /// application flickering on the microphone produces an alert a second - and reading every line
    /// of the journal to discover that it is not yet full is work done thousands of times to answer
    /// "no". The line count is tracked in memory instead: read once for a given path, then
    /// incremented per append, so the check is O(1) and the bound is still exact.
    ///
    /// The count is re-derived after every trim and whenever it is not known, so an externally
    /// modified journal self-corrects on the next trim rather than drifting.
    /// </remarks>
    private static void Trim(string path)
    {
        if (!LineCounts.TryGetValue(path, out var count))
        {
            count = CountLines(path);
        }
        LineCounts[path] = count;
        if (count <= MaxEntries)
        {
            return;
        }

        var lines = File.ReadAllLines(path);
        LineCounts[path] = lines.Length;
        if (lines.Length <= MaxEntries)
        {
            return;
        }
        var temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 4096,
                       FileOptions.WriteThrough))
            using (var writer = new StreamWriter(stream))
            {
                foreach (var line in lines.Skip(lines.Length - MaxEntries))
                {
                    writer.WriteLine(line);
                }
                writer.Flush();
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, path, overwrite: true);
            LineCounts[path] = MaxEntries;
        }
        finally
        {
            try { File.Delete(temporaryPath); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    private static int CountLines(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return 0;
            }
            var lines = 0;
            using var reader = new StreamReader(path, System.Text.Encoding.UTF8);
            while (reader.ReadLine() is not null)
            {
                lines++;
            }
            return lines;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return 0;
        }
    }

    private static void PreserveOversizedJournal(string path)
    {
        if (!File.Exists(path) || new FileInfo(path).Length <= MaximumJournalBytes)
        {
            return;
        }
        // The journal is about to be moved aside, so whatever was counted no longer describes it.
        LineCounts.Remove(path);
        var preserved = path + ".oversized-" + DateTime.UtcNow.ToString(
            "yyyyMMddHHmmssfff", CultureInfo.InvariantCulture);
        File.Move(path, preserved);
        PurgeOldPreservedJournals(path);
    }

    /// <summary>
    /// Keeps the most recent preserved journals and deletes the rest.
    /// </summary>
    /// <remarks>
    /// A journal was set aside whenever it passed 16 MiB and nothing ever removed the copy, so a
    /// machine producing alerts steadily accumulated 16 MiB files in the operator's own profile
    /// indefinitely. Keeping a few is the point - they are evidence - but keeping all of them is a
    /// disk-consumption bug in a tool whose whole promise is that it does not act on its own.
    /// </remarks>
    private static void PurgeOldPreservedJournals(string path)
    {
        const int KeepPreserved = 3;
        try
        {
            var directory = Path.GetDirectoryName(path);
            if (string.IsNullOrEmpty(directory))
            {
                return;
            }
            var preserved = Directory
                .GetFiles(directory, Path.GetFileName(path) + ".oversized-*")
                .OrderByDescending(file => file, StringComparer.Ordinal)
                .Skip(KeepPreserved);
            foreach (var stale in preserved)
            {
                try { File.Delete(stale); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            // Housekeeping only; a failure here must never affect recording an alert.
        }
    }
}
