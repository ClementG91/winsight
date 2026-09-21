using WinSight.AvMonitor;
using WinSight.Presence;
using WinSight.Reporting;

namespace WinSight.Application;

public static partial class Adapters
{
    public static ToolReport CameraMic(bool flaggedOnly)
    {
        var acquisition = new CapabilityAccessReader().ReadWithCoverage();
        var usages = acquisition.Items;
        var b = new ToolReport.Builder("camera-mic");
        foreach (var u in usages.Where(u => !flaggedOnly || u.Active).OrderByDescending(u => u.Active))
        {
            var device = u.Kind == DeviceKind.Webcam ? "webcam" : "mic";
            b.Add(
                u.Active ? Severity.Notable : Severity.Info,
                $"{device}/{u.App}",
                u.Active ? "in use now" : $"last used {u.LastStop?.ToString("u") ?? u.LastStart?.ToString("u") ?? "unknown"}",
                new Dictionary<string, string?>
                {
                    ["kind"] = device,
                    ["app"] = u.App,
                    ["packaged"] = u.Packaged.ToString(),
                    ["active"] = u.Active.ToString(),
                    ["lastStart"] = u.LastStart?.ToString("o"),
                    ["lastStop"] = u.LastStop?.ToString("o"),
                });
        }
        AddCoverageFinding(b, acquisition);
        return b.Build($"{usages.Count} recorded use(s), {usages.Count(u => u.Active)} live now{CoverageSuffix(acquisition)}");
    }

    /// <summary>
    /// When this machine woke, and which of those wakes mean somebody was physically at it.
    /// </summary>
    /// <remarks>
    /// <b>Deliberately not in the default overview.</b> This is a timeline you consult when you
    /// suspect somebody was at your desk, not a check that should speak on every routine scan: a
    /// machine in daily use wakes constantly, and the one thing that would make a wake suspicious —
    /// knowing a person caused it — is exactly what Windows most often declines to record.
    /// </remarks>
    public static ToolReport Presence(bool flaggedOnly)
    {
        var report = new PresenceScanner().Scan();
        var builder = new ToolReport.Builder("presence");
        foreach (var wake in report.Wakes.Where(wake => !flaggedOnly || wake.IndicatesPresence))
        {
            builder.Add(
                // Only a wake attributable to a human hand is notable. A timer, a Wake-on-LAN packet
                // or a cause Windows never recorded are all reported without being dressed up as a
                // visitor — measured on a real desktop, none of twelve resumes was a person.
                wake.IndicatesPresence ? Severity.Notable : Severity.Info,
                $"{wake.WokeUtc:u} {wake.Cause}",
                Describe(wake),
                new Dictionary<string, string?>
                {
                    ["wokeUtc"] = wake.WokeUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                    ["sleptUtc"] = wake.SleptUtc?.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                    ["cause"] = wake.Cause.ToString(),
                    ["source"] = wake.Source,
                    ["indicatesPresence"] = wake.IndicatesPresence.ToString(),
                });
        }

        if (report.Unreadable)
        {
            // An empty timeline and an unreadable log look identical from outside, and only one of
            // them is a fact about the machine.
            builder.Add(
                Severity.Notable,
                "resume history unavailable",
                "the Windows System event log could not be queried",
                new Dictionary<string, string?>
                {
                    ["kind"] = "acquisitionCoverage",
                    ["unreadableSources"] = "1",
                });
            return builder.Build("the System event log could not be read, so no resume history is available");
        }
        if (report.UnreadableItems > 0)
        {
            builder.Add(
                Severity.Notable,
                "resume history incomplete",
                $"{report.UnreadableItems} event record(s) could not be parsed",
                new Dictionary<string, string?>
                {
                    ["kind"] = "acquisitionCoverage",
                    ["unreadableItems"] = report.UnreadableItems.ToString(System.Globalization.CultureInfo.InvariantCulture),
                });
        }
        return builder.Build(report.UnreadableItems > 0
            ? $"resume history incomplete: {report.UnreadableItems} event record(s) unreadable"
            : report.Wakes.Count == 0
            ? "no resume from sleep recorded"
            : $"{report.Wakes.Count} resume(s), {report.PresenceCount} indicating someone was physically present");
    }

    private static string Describe(WakeRecord wake)
    {
        var asleep = wake.Asleep is { } duration ? $" after {SleepDuration(duration)} asleep" : string.Empty;
        return wake.Cause switch
        {
            WakeCause.PhysicalInput => $"woken by {wake.Source ?? "a button or input device"}{asleep} — somebody was at the machine",
            WakeCause.Network => $"woken over the network by {wake.Source}{asleep} — a packet, not a person",
            WakeCause.Timer => $"woken by scheduled work{asleep}",
            WakeCause.Device => $"woken by {wake.Source}{asleep} — Windows named the device but not why",
            _ => $"woken{asleep}, cause not recorded by Windows",
        };
    }

    /// <summary>
    /// A sleep length that keeps its days. The <c>hh\:mm</c> format it replaced shows the hours
    /// component only, so a machine asleep for 30 hours read "06:00" - a weekend reported as a nap,
    /// on the one check that asks how long somebody was away.
    /// </summary>
    internal static string SleepDuration(TimeSpan duration) =>
        duration.TotalDays >= 1
            ? string.Create(
                System.Globalization.CultureInfo.InvariantCulture,
                $"{(int)duration.TotalDays} d {duration.Hours:D2}:{duration.Minutes:D2}")
            : string.Create(
                System.Globalization.CultureInfo.InvariantCulture,
                $"{duration.Hours:D2}:{duration.Minutes:D2}");
}
