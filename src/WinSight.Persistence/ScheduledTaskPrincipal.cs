using System.Security.Principal;
using System.Xml;
using System.Xml.Linq;

namespace WinSight.Persistence;

/// <summary>
/// WS-46. The account a scheduled task runs as. The Task Scheduler expands the variables of an Exec
/// action in that account's environment, so a SYSTEM task's <c>%APPDATA%</c> is under
/// <c>systemprofile</c>, never under the profile of whoever runs the scan.
/// </summary>
internal static class ScheduledTaskPrincipal
{
    private static readonly Dictionary<string, string> WellKnown = new(StringComparer.OrdinalIgnoreCase)
    {
        ["SYSTEM"] = "S-1-5-18",
        [@"NT AUTHORITY\SYSTEM"] = "S-1-5-18",
        ["LocalSystem"] = "S-1-5-18",
        ["LOCAL SERVICE"] = "S-1-5-19",
        [@"NT AUTHORITY\LOCAL SERVICE"] = "S-1-5-19",
        ["LocalService"] = "S-1-5-19",
        ["NETWORK SERVICE"] = "S-1-5-20",
        [@"NT AUTHORITY\NETWORK SERVICE"] = "S-1-5-20",
        ["NetworkService"] = "S-1-5-20",
    };

    /// <summary>
    /// The SID the task's actions run as; null when it runs as whoever is logged on (a group
    /// principal), or when naming the account would need a directory lookup.
    /// </summary>
    internal static string? Sid(string xml, Func<string, string?>? translateLocalAccount = null)
    {
        XElement? root;
        try
        {
            root = XDocument.Parse(xml).Root;
        }
        catch (XmlException)
        {
            return null;
        }
        if (root is null)
        {
            return null;
        }
        var context = Child(root, "Actions")?.Attribute("Context")?.Value;
        var principals = Child(root, "Principals")?.Elements()
            .Where(element => element.Name.LocalName == "Principal").ToList() ?? [];
        var principal = principals.FirstOrDefault(p => string.Equals(p.Attribute("id")?.Value, context, StringComparison.Ordinal))
            ?? principals.FirstOrDefault();
        var user = principal is null ? null : Child(principal, "UserId")?.Value.Trim();
        if (string.IsNullOrEmpty(user))
        {
            return null;
        }
        if (user.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
        {
            return user;
        }
        if (WellKnown.TryGetValue(user, out var sid))
        {
            return sid;
        }
        // Only a machine-local account is translated: LSA answers it from the local SAM. A bare or
        // domain name would send the lookup to a domain controller, and this scan stays off the network.
        var separator = user.IndexOf('\\', StringComparison.Ordinal);
        return separator > 0 && user[..separator].Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase)
            ? (translateLocalAccount ?? TranslateLocalAccount)(user)
            : null;
    }

    /// <summary>
    /// The loader for a task running as <paramref name="sid"/>: null for the scanner's own account or
    /// an unknown one, else that account's variables (none at all when its profile is unknown, so
    /// they stay unexpanded rather than pointing into the scanner's profile).
    /// </summary>
    internal static LoaderContext? Loader(string? sid, string? scannerSid, Dictionary<string, LoaderContext> cache)
    {
        if (sid is null || sid.Equals(scannerSid, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        if (!cache.TryGetValue(sid, out var loader))
        {
            loader = LoaderContext.ForAccount(
                AccountEnvironment.For(sid) ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));
            cache[sid] = loader;
        }
        return loader;
    }

    private static XElement? Child(XElement parent, string localName) =>
        parent.Elements().FirstOrDefault(element => element.Name.LocalName == localName);

    private static string? TranslateLocalAccount(string account)
    {
        try
        {
            return new NTAccount(account).Translate(typeof(SecurityIdentifier)).Value;
        }
        catch (SystemException)
        {
            return null;
        }
    }
}
