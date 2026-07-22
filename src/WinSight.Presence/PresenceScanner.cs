using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Xml.Linq;

namespace WinSight.Presence;

/// <summary>One resume from sleep, with what Windows said caused it.</summary>
/// <param name="WokeUtc">When the machine came back.</param>
/// <param name="SleptUtc">When it went to sleep, when the record carries it.</param>
/// <param name="Cause">The cause, classified by <see cref="WakeSource"/>.</param>
/// <param name="Source">The device Windows named, when it named one.</param>
public sealed record WakeRecord(
    DateTimeOffset WokeUtc,
    DateTimeOffset? SleptUtc,
    WakeCause Cause,
    string? Source)
{
    /// <summary>How long the machine was asleep, when both ends of the interval are known.</summary>
    public TimeSpan? Asleep => SleptUtc is { } slept && WokeUtc > slept ? WokeUtc - slept : null;

    /// <summary>Somebody was physically at the machine.</summary>
    public bool IndicatesPresence => WakeSource.IndicatesPresence(Cause);
}

/// <summary>What the scan managed to read, so an empty result is never mistaken for a quiet machine.</summary>
/// <param name="Wakes">The resumes read, newest first.</param>
/// <param name="Unreadable">
/// True when the event log could not be queried at all. Distinct from "queried and found nothing",
/// which is the confusion this flag exists to prevent.
/// </param>
public sealed record PresenceReport(IReadOnlyList<WakeRecord> Wakes, bool Unreadable)
{
    public int PresenceCount => Wakes.Count(wake => wake.IndicatesPresence);
}

/// <summary>Where resume records are read from. A seam, so the rules above need no event log.</summary>
public interface IWakeEventSource
{
    /// <summary>Every resume the caller is allowed to see. Never throws; see <see cref="Unreadable"/>.</summary>
    IEnumerable<WakeRecord> Enumerate(int max);

    /// <summary>True when the source could not be read at all.</summary>
    bool Unreadable { get; }
}

/// <summary>
/// Reads resume records from the Windows System event log.
/// </summary>
/// <remarks>
/// <b>Why the System log and not the Security log.</b> Logon failures would be the richer signal and
/// they live in the Security log, which requires Administrator — measured: reading it unelevated
/// throws. WinSight's default mode is unprivileged, so the check is built on what is actually
/// readable there. The System log is, and it carries the sleep/resume timeline including the wake
/// source.
///
/// <b>Why the registry route was rejected.</b> USB device history under
/// <c>SYSTEM\CurrentControlSet\Enum</c> looks like the obvious source for "what was plugged in while
/// I was away". The device keys are readable unelevated, but their <c>Properties</c> subkey — which
/// is where the first-seen and last-arrival timestamps live — throws <c>SecurityException</c>
/// without elevation. An inventory of devices with no dates cannot answer the question the check
/// exists to ask, and would have looked complete while doing it.
/// </remarks>
public sealed class SystemLogWakeSource : IWakeEventSource
{
    private const string PowerTroubleshooterProvider = "Microsoft-Windows-Power-Troubleshooter";
    private const int ResumeEventId = 1;

    private bool _unreadable;

    public bool Unreadable => _unreadable;

    public IEnumerable<WakeRecord> Enumerate(int max)
    {
        _unreadable = false;
        if (max <= 0)
        {
            return [];
        }
        try
        {
            return Read(max);
        }
        catch (Exception ex) when (ex is EventLogException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or InvalidOperationException)
        {
            // The log can be disabled, cleared or restricted. An empty list is then not a fact about
            // the machine, and saying so is the whole point of this flag.
            _unreadable = true;
            return [];
        }
    }

    private static List<WakeRecord> Read(int max)
    {
        var query = new EventLogQuery(
            "System",
            PathType.LogName,
            $"*[System[Provider[@Name='{PowerTroubleshooterProvider}'] and (EventID={ResumeEventId})]]")
        {
            ReverseDirection = true,
        };

        var wakes = new List<WakeRecord>();
        using var reader = new EventLogReader(query);
        while (wakes.Count < max && reader.ReadEvent() is { } entry)
        {
            using (entry)
            {
                if (Parse(entry) is { } wake)
                {
                    wakes.Add(wake);
                }
            }
        }
        return wakes;
    }

    /// <summary>
    /// Reads one record from the event's own XML rather than its rendered message.
    /// </summary>
    /// <remarks>
    /// The rendered message is localised — this machine renders it in French — so parsing it would
    /// make the check work only where WinSight happens to have been developed. The XML carries the
    /// numeric type and the raw device name in every locale.
    /// </remarks>
    internal static WakeRecord? Parse(EventRecord entry)
    {
        XElement root;
        try
        {
            root = XElement.Parse(entry.ToXml());
        }
        catch (System.Xml.XmlException)
        {
            return null;
        }

        var data = root.Descendants()
            .Where(element => element.Name.LocalName == "Data")
            .ToDictionary(
                element => element.Attribute("Name")?.Value ?? string.Empty,
                element => element.Value,
                StringComparer.Ordinal);

        var woke = entry.TimeCreated?.ToUniversalTime();
        if (woke is null)
        {
            // Without a time the record cannot be placed on a timeline, and a wake with no "when" is
            // not something to show an operator.
            return null;
        }

        var sourceType = data.TryGetValue("WakeSourceType", out var typeText)
            && int.TryParse(typeText, CultureInfo.InvariantCulture, out var parsedType)
                ? parsedType
                : 0;
        data.TryGetValue("WakeSourceText", out var sourceText);

        return new WakeRecord(
            new DateTimeOffset(woke.Value, TimeSpan.Zero),
            ParseTime(data, "SleepTime"),
            WakeSource.Classify(sourceType, sourceText),
            string.IsNullOrWhiteSpace(sourceText) ? null : sourceText);
    }

    private static DateTimeOffset? ParseTime(Dictionary<string, string> data, string field) =>
        data.TryGetValue(field, out var value)
        && DateTimeOffset.TryParse(
            value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed)
            ? parsed.ToUniversalTime()
            : null;
}

/// <summary>
/// Reports when this machine woke, and which of those wakes mean somebody was physically there.
/// </summary>
/// <remarks>
/// The Windows answer to DoNotDisturb, and deliberately a narrower claim than the macOS one. Apple's
/// tool watches a lid open, which is unambiguous. Windows reports a numeric wake source that,
/// measured over twelve resumes on a real desktop, was <i>Unknown</i> seven times and a network
/// adapter five times — never once a person. So this reports the timeline, names the cause in
/// Windows' own terms, and flags only the wakes it can honestly attribute to a human hand.
/// </remarks>
public sealed class PresenceScanner(IWakeEventSource? source = null)
{
    /// <summary>A timeline, not an archive: recent history is what answers "was someone here?".</summary>
    public const int DefaultMax = 50;

    private readonly IWakeEventSource _source = source ?? new SystemLogWakeSource();

    public PresenceReport Scan(int max = DefaultMax)
    {
        var wakes = _source.Enumerate(max)
            .OrderByDescending(wake => wake.WokeUtc)
            .ToArray();

        return new PresenceReport(wakes, _source.Unreadable);
    }
}
