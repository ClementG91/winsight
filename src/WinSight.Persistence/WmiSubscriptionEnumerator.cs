using System.Management;

namespace WinSight.Persistence;

/// <summary>
/// Permanent WMI event subscriptions — a stealthy, fileless persistence technique:
/// an __EventFilter (trigger) bound to an event consumer (payload) in the
/// root\subscription namespace. This enumerates the ACTION side: CommandLine and
/// ActiveScript consumers, whose command/script is what runs. Any entry here is
/// notable — legitimate software rarely installs these.
/// </summary>
public sealed class WmiSubscriptionEnumerator : IAutostartEnumerator
{
    public string Surface => "WMI subscriptions";

    public IEnumerable<RawAutostart> Enumerate()
    {
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
    }

    private static IReadOnlyList<RawAutostart> Query(string wql, Func<ManagementBaseObject, string?> commandOf)
    {
        var rows = new List<RawAutostart>();
        try
        {
            var scope = new ManagementScope(@"\\.\root\subscription");
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(wql));
            foreach (ManagementBaseObject o in searcher.Get())
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
            // Namespace unavailable / access denied — no subscriptions surfaced.
        }
        return rows;
    }
}
