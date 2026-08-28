using System.Management;

namespace WinSight.Persistence;

/// <summary>
/// Permanent WMI event subscriptions, a stealthy, fileless persistence technique:
/// an __EventFilter (trigger) bound to an event consumer (payload) in the
/// root\subscription namespace. This enumerates the ACTION side: CommandLine and
/// ActiveScript consumers, whose command/script is what runs. Any entry here is
/// notable, legitimate software rarely installs these.
/// </summary>
public sealed class WmiSubscriptionEnumerator : IAutostartEnumerator
{
    private int _unreadable;

    public string Surface => "WMI subscriptions";

    /// <inheritdoc />
    /// <remarks>
    /// <b>This was the one enumerator that could not say it had been refused.</b> Every query was
    /// wrapped in a catch that swallowed ManagementException and UnauthorizedAccessException alike,
    /// so an unelevated scan - where root\subscription is frequently denied - reported "no
    /// subscriptions" with IsPartial false. WMI persistence is fileless and among the stealthiest
    /// techniques there is; reporting a clean surface because Windows refused to answer is the worst
    /// possible outcome on exactly the surface where it matters most.
    /// </remarks>
    public int UnreadableLocations => Volatile.Read(ref _unreadable);

    public IEnumerable<RawAutostart> Enumerate()
    {
        Volatile.Write(ref _unreadable, 0);
        // CommandLineEventConsumer runs a command; ActiveScriptEventConsumer runs an
        // inline/one-file script.
        foreach (var e in Query(
                     "SELECT Name, CommandLineTemplate FROM CommandLineEventConsumer",
                     o => o["CommandLineTemplate"] as string))
        {
            yield return e;
        }
        foreach (var e in Query(
                     "SELECT Name, ScriptFileName, ScriptText FROM ActiveScriptEventConsumer",
                     o => o["ScriptFileName"] as string ?? "<inline script>"))
        {
            yield return e;
        }

        // __EventFilter and __FilterToConsumerBinding are deliberately NOT emitted as entries.
        //
        // They complete the picture of a subscription and an operator investigating a consumer
        // wants them - but neither names an image, and every entry in this report is graded by the
        // image model. A WQL query has no file to resolve, so each stock Windows filter (the SCM
        // Event Log filter ships with the OS) would arrive with "no resolvable image" and be flagged
        // on every machine in the world. Trading a real blind spot for a guaranteed false positive
        // is not an improvement; the honest form of this is an image-free presentation, recorded in
        // docs/DETECTIONS.md as a known gap rather than shipped as noise.
    }

    private List<RawAutostart> Query(string wql, Func<ManagementBaseObject, string?> commandOf)
    {
        var rows = new List<RawAutostart>();
        try
        {
            var scope = new ManagementScope(@"\\.\root\subscription");
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(wql));
            // The collection owns an unmanaged enumerator and a COM reference; a bare
            // foreach over searcher.Get() left both to the finaliser.
            using var results = searcher.Get();
            foreach (ManagementBaseObject o in results)
            {
                using (o)
                {
                    var name = o["Name"] as string ?? string.Empty;
                    var command = commandOf(o) ?? string.Empty;
                    rows.Add(new RawAutostart(
                        AutostartVector.WmiSubscription, name,
                        $"root\\subscription:{o.ClassPath.ClassName}", command));
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException)
        {
            // Namespace unavailable or access denied. Counted, because "WMI would not answer" and
            // "there are no subscriptions" are different statements and only one is reassuring.
            Interlocked.Increment(ref _unreadable);
        }
        return rows;
    }
}
