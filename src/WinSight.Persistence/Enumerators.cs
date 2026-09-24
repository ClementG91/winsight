using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>A raw autostart record before image resolution / signature checking.</summary>
/// <param name="OverridesMachineClass">
/// A per-user COM registration that points a class the machine also registers at a different
/// server: the per-user value wins, so this is the class being redirected (WS-54).
/// </param>
/// <param name="Loader">
/// How the process that loads the command sees the machine, when that is not the scanner's own
/// view: a 32-bit process, or another account (WS-45, WS-46). Null for the scanner's view.
/// </param>
public readonly record struct RawAutostart(
    AutostartVector Vector, string Name, string Location, string Command, bool OverridesMachineClass = false,
    LoaderContext? Loader = null)
{
    /// <summary>
    /// The loader for something read from <paramref name="view"/> and loaded in-process: a 32-bit
    /// process for the WOW6432Node half, the scanner's own view otherwise.
    /// </summary>
    internal static LoaderContext? LoaderFor(RegistryView view) =>
        view == RegistryView.Registry32 ? LoaderContext.Wow64Process : null;
}

/// <summary>An autostart surface WinSight knows how to enumerate.</summary>
public interface IAutostartEnumerator
{
    /// <summary>Human-readable name of the surface (for reporting/telemetry-free logs).</summary>
    string Surface { get; }

    /// <summary>Enumerates the raw autostart records currently present in this surface.</summary>
    IEnumerable<RawAutostart> Enumerate();

    /// <summary>
    /// Locations to watch to know this surface may have changed, for real-time (Guardian)
    /// monitoring. Empty — the default — means the surface is not watched live yet; it is still
    /// covered by the on-start reconciliation diff, so an unwatched surface is honestly
    /// "polled on start", never silently unmonitored.
    /// </summary>
    IReadOnlyList<PersistenceWatchTarget> WatchTargets => Array.Empty<PersistenceWatchTarget>();

    /// <summary>
    /// How many locations the last <see cref="Enumerate"/> had to skip because it was not allowed
    /// to read them. Valid once that enumeration has been fully consumed; each call resets it.
    /// </summary>
    /// <remarks>
    /// Zero by default, which is the truth for every surface readable by any user.
    ///
    /// <b>Why a scanner must count its own refusals.</b> Measured on a real machine, the same scan
    /// returned 8 546 entries unelevated and 8 756 elevated: 210 autostart items — scheduled tasks
    /// belonging to browser, graphics-driver and cloud-sync updaters, and <i>one already flagged as
    /// suspicious</i> — were simply absent, with no indication anything had been skipped. An
    /// operator reading that scan sees a clean surface, and "clean" and "I was not allowed to look"
    /// are not the same statement. Counting turns the second into something the report can say.
    /// </remarks>
    int UnreadableLocations => 0;

    /// <summary>
    /// Whether a successful enumeration with zero unreadable locations proves absence. Opt in
    /// only when every skipped read is counted; an unknown result must not erase Guardian state.
    /// </summary>
    bool CanConfirmAbsence => false;

    /// <summary>
    /// Location prefixes, spelled as <see cref="RawAutostart.Location"/> is, that cover every read
    /// counted in <see cref="UnreadableLocations"/>; null when any failure cannot be attributed.
    /// </summary>
    /// <remarks>
    /// Lets a partly readable source confirm absence where it did read: an identity outside every
    /// scope was in readable territory. A source that cannot attribute a failure returns null and
    /// keeps the conservative whole-source rule.
    /// </remarks>
    IReadOnlyCollection<string>? UnreadableScopes => null;
}

/// <summary>
/// The classic Run/RunOnce registry autostart keys, across HKLM+HKCU and both the
/// 64-bit and 32-bit (WOW6432Node) views, a favourite malware persistence spot.
/// </summary>
public sealed class RunKeyEnumerator : IAutostartEnumerator
{
    private int _unreadable;
    public int UnreadableLocations => _unreadable;
    public bool CanConfirmAbsence => true;

    private static readonly string[] SubKeys =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    };

    public string Surface => "Run keys";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = BuildWatchTargets();

    /// <summary>
    /// The registry views worth reading for <paramref name="hive"/>. WOW64 redirects
    /// <c>HKLM\SOFTWARE</c>, never the user's own hive, so reading HKCU under both views returns the
    /// same values twice.
    /// </summary>
    /// <remarks>
    /// The duplicate was not merely noise: Guardian saw every user-level startup item as two arrivals,
    /// so it announced them as a coalesced burst - a balloon - instead of opening the decision window
    /// that Allow/Block exists for, and journalled each arrival twice.
    /// </remarks>
    private static RegistryView[] ViewsFor(RegistryHive hive) =>
        hive == RegistryHive.CurrentUser
            ? [RegistryView.Registry64]
            : [RegistryView.Registry64, RegistryView.Registry32];

    private static PersistenceWatchTarget[] BuildWatchTargets()
    {
        var targets = new List<PersistenceWatchTarget>();
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        {
            foreach (var view in ViewsFor(hive))
            {
                foreach (var sub in SubKeys)
                {
                    targets.Add(PersistenceWatchTarget.Registry(hive, view, sub));
                }
            }
        }
        return targets.ToArray();
    }

    public IEnumerable<RawAutostart> Enumerate()
    {
        _unreadable = 0;
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        {
            foreach (var view in ViewsFor(hive))
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                foreach (var sub in SubKeys)
                {
                    foreach (var e in ReadValues(baseKey, hive, view, sub))
                    {
                        yield return e;
                    }
                }
            }
        }
    }

    private IEnumerable<RawAutostart> ReadValues(
        RegistryKey baseKey, RegistryHive hive, RegistryView view, string sub)
    {
        RegistryKey? key;
        try
        {
            key = baseKey.OpenSubKey(sub);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            _unreadable++;
            yield break;
        }
        if (key is null)
        {
            yield break;
        }

        using (key)
        {
            // The path as it is actually spelled in this view, not the unredirected one. A finding
            // reported under HKLM\SOFTWARE\... for a value that lives in
            // HKLM\SOFTWARE\WOW6432Node\... sends the operator to a key that does not contain it -
            // and, because write attribution matches an observed kernel write against this string
            // as a prefix, it also made every 32-bit persistence write unattributable by
            // construction: the kernel reports the WOW6432Node path and nothing here ever said it.
            var location = $"{HiveName(hive)}\\{RegistryViews.Describe(sub, view)} [{view}]";
            foreach (var name in key.GetValueNames())
            {
                if (key.GetValue(name) is string command && command.Length > 0)
                {
                    yield return new RawAutostart(AutostartVector.RunKey, name, location, command);
                }
            }
        }
    }

    private static string HiveName(RegistryHive hive) =>
        hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
}

/// <summary>
/// Auto-start Windows services and drivers (Start type boot/system/auto) read from
/// the service control database in the registry, keyed by ImagePath. For
/// svchost-hosted services the ImagePath is just svchost.exe (signed Microsoft), the
/// REAL payload is the Parameters\ServiceDll, so that DLL is surfaced as its own
/// entry; otherwise a malicious service DLL rides invisibly under a trusted host.
/// </summary>
public sealed class ServiceEnumerator : IAutostartEnumerator
{
    private int _unreadable;
    public int UnreadableLocations => _unreadable;
    public bool CanConfirmAbsence => true;

    private const string Root = @"SYSTEM\CurrentControlSet\Services";
    private readonly List<string> _unreadableScopes = [];

    public string Surface => "Services & drivers";

    public IReadOnlyCollection<string>? UnreadableScopes => _unreadableScopes;

    // Watch the whole Services subtree: a new service is a new subkey (Name) and a repurposed one
    // is a changed ImagePath/Start value (LastSet), both under this root.
    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(
            RegistryHive.LocalMachine, RegistryView.Registry64, Root, watchSubtree: true),
    };

    public IEnumerable<RawAutostart> Enumerate()
    {
        _unreadable = 0;
        _unreadableScopes.Clear();
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var services = baseKey.OpenSubKey(Root);
        if (services is null)
        {
            yield break;
        }

        foreach (var name in services.GetSubKeyNames())
        {
            var entries = new List<RawAutostart>(2);
            try
            {
                using var svc = services.OpenSubKey(name);
                // Start: 0=boot 1=system 2=auto 3=manual 4=disabled. Only auto-starting.
                if (svc?.GetValue("ImagePath") is string image && image.Length > 0 &&
                    svc.GetValue("Start") is int start && start <= 2)
                {
                    entries.Add(new RawAutostart(
                        AutostartVector.Service, name, $"HKLM\\{Root}\\{name}", image));

                    // svchost payload: the hosted DLL is what actually runs.
                    using var parameters = svc.OpenSubKey("Parameters");
                    if (parameters?.GetValue("ServiceDll") is string dll && dll.Trim().Length > 0)
                    {
                        entries.Add(new RawAutostart(
                            AutostartVector.Service, $"{name} (ServiceDll)",
                            $"HKLM\\{Root}\\{name}\\Parameters [ServiceDll]", dll));
                    }
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
            {
                _unreadable++;
                _unreadableScopes.Add($"HKLM\\{Root}\\{name}");
            }

            foreach (var e in entries)
            {
                yield return e;
            }
        }
    }
}

/// <summary>
/// The Winlogon logon hooks: the programs the OS launches around sign-in.
/// Defaults are explorer.exe and userinit.exe; malware appends its own comma-
/// separated payload here, so any EXTRA command beyond the default is notable.
/// Covers HKLM (machine-wide) AND HKCU, a per-user override is a quieter,
/// no-admin variant of the same hijack. See <c>Values</c> for which values are
/// read and which are deliberately not.
/// </summary>
public sealed class WinlogonEnumerator : IAutostartEnumerator
{
    public bool CanConfirmAbsence => true;

    private const string Path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

    /// <summary>
    /// The Winlogon values that name something Windows still executes.
    /// </summary>
    /// <remarks>
    /// <b>What was missing.</b> Only Shell and Userinit were read, and the surface was described as
    /// if those were the whole of it. Three more values on the same key launch a program at logon
    /// and were invisible to the scan:
    ///
    /// <list type="bullet">
    /// <item><c>Taskman</c> - Winlogon launches this instead of Task Manager. An operator pressing
    /// Ctrl+Shift+Esc runs whatever it names, which is both persistence and a way to stop somebody
    /// looking at the process list.</item>
    /// <item><c>AppSetup</c> - userinit runs it at every logon, before the shell.</item>
    /// <item><c>UIHost</c> - the logon UI host, launched as SYSTEM before anybody signs in.</item>
    /// </list>
    ///
    /// <c>GinaDLL</c> is read for the opposite reason to the others: modern Windows does not
    /// execute it, so nothing legitimate sets it, and its mere presence on a supported machine is
    /// the finding. Reading a value the OS ignores is normally noise; reading one that should not
    /// exist at all is not.
    ///
    /// <b>Deliberately still absent.</b> <c>Notify</c> and <c>VmApplet</c> are legacy in the same
    /// way but are set by real software that predates Vista, so enumerating them adds findings an
    /// operator cannot act on.
    /// </remarks>
    private static readonly string[] Values =
        ["Shell", "Userinit", "Taskman", "AppSetup", "UIHost", "GinaDLL"];

    /// <summary>
    /// The values this enumerator reads. Public because it is a claim about coverage, and a claim
    /// about coverage that nothing can check is the kind this project keeps finding wrong.
    /// </summary>
    public static IReadOnlyList<string> ExecutedValues => Values;

    public string Surface => "Winlogon logon hooks";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path),
        PersistenceWatchTarget.Registry(RegistryHive.CurrentUser, RegistryView.Registry64, Path),
    };

    public IEnumerable<RawAutostart> Enumerate()
    {
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(Path);
            if (key is null)
            {
                continue;
            }

            var hiveName = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
            foreach (var value in Values)
            {
                if (key.GetValue(value) is not string raw)
                {
                    continue;
                }
                foreach (var command in SplitCommands(raw))
                {
                    yield return new RawAutostart(
                        AutostartVector.Winlogon, value, $"{hiveName}\\{Path} [{value}]", command);
                }
            }
        }
    }

    /// <summary>
    /// Splits a Winlogon Shell/Userinit value into its individual commands. The value
    /// is a comma-separated list (e.g. "userinit.exe," or "explorer.exe,malware.exe");
    /// empties from trailing commas are dropped.
    /// </summary>
    public static IEnumerable<string> SplitCommands(string raw) =>
        raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
