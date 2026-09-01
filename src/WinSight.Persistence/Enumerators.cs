using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>A raw autostart record before image resolution / signature checking.</summary>
public readonly record struct RawAutostart(
    AutostartVector Vector, string Name, string Location, string Command);

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
    /// belonging to Brave, Edge, NVIDIA, OneDrive and Google updaters, and <i>one already flagged as
    /// suspicious</i> — were simply absent, with no indication anything had been skipped. An
    /// operator reading that scan sees a clean surface, and "clean" and "I was not allowed to look"
    /// are not the same statement. Counting turns the second into something the report can say.
    /// </remarks>
    int UnreadableLocations => 0;
}

/// <summary>
/// The classic Run/RunOnce registry autostart keys, across HKLM+HKCU and both the
/// 64-bit and 32-bit (WOW6432Node) views, a favourite malware persistence spot.
/// </summary>
public sealed class RunKeyEnumerator : IAutostartEnumerator
{
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

    private static PersistenceWatchTarget[] BuildWatchTargets()
    {
        var targets = new List<PersistenceWatchTarget>();
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
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
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
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

    private static IEnumerable<RawAutostart> ReadValues(
        RegistryKey baseKey, RegistryHive hive, RegistryView view, string sub)
    {
        RegistryKey? key;
        try
        {
            key = baseKey.OpenSubKey(sub);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
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
    private const string Root = @"SYSTEM\CurrentControlSet\Services";

    public string Surface => "Services & drivers";

    // Watch the whole Services subtree: a new service is a new subkey (Name) and a repurposed one
    // is a changed ImagePath/Start value (LastSet), both under this root.
    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(
            RegistryHive.LocalMachine, RegistryView.Registry64, Root, watchSubtree: true),
    };

    public IEnumerable<RawAutostart> Enumerate()
    {
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
                // Skip service keys we cannot read.
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

/// <summary>
/// Scheduled Tasks, read from the Task Scheduler service. Each task's Exec action Command is an
/// autostart command. A favourite modern persistence spot.
/// </summary>
/// <remarks>
/// This used to parse the XML files under <c>%SystemRoot%\System32\Tasks</c> directly, to avoid a
/// COM dependency. That directory is administrators-only and <c>Directory.GetFiles</c> throws for
/// the whole tree rather than skipping what it cannot read, so unelevated WinSight reported
/// <b>zero</b> scheduled tasks while still listing the surface as covered — measured, 0 unelevated
/// against 104 elevated. The service answers without elevation and answers better (195 on the same
/// machine, because it lists what is registered rather than what has a readable file), and it hands
/// back the same XML, so the parsing below is unchanged. See <see cref="ComScheduledTaskSource"/>.
/// </remarks>
public sealed class ScheduledTaskEnumerator(IScheduledTaskSource? source = null) : IAutostartEnumerator
{
    private static readonly string TasksRoot =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");

    private readonly IScheduledTaskSource _source = source ?? new ComScheduledTaskSource();
    private int _unreadable;

    public string Surface => "Scheduled Tasks";

    // A scheduled task is still a file under \System32\Tasks even when read through the service, so
    // the live watcher keeps watching the tree — directory change notifications do not require the
    // read access that opening the files does.
    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.FileSystem(TasksRoot, includeSubdirectories: true),
    };

    /// <inheritdoc />
    /// <remarks>
    /// Reported as one unreadable location, not a count: when the service cannot be reached the
    /// number of tasks behind it is exactly what is unknown.
    /// </remarks>
    public int UnreadableLocations => _unreadable;

    public IEnumerable<RawAutostart> Enumerate()
    {
        var tasks = _source.Enumerate().ToList();
        _unreadable = _source.Unreadable ? 1 : 0;
        foreach (var task in tasks)
        {
            if (!TryParseTaskCommands(task.Xml, out var commands, out var unresolvedComHandlers))
            {
                _unreadable++;
                continue;
            }
            // A COM handler this scan could not resolve to a file is a task whose code it never
            // looked at. Counted rather than guessed at.
            _unreadable += unresolvedComHandlers;
            foreach (var command in commands)
            {
                yield return new RawAutostart(
                    AutostartVector.ScheduledTask,
                    task.Path.TrimStart('\\'),
                    Path.Combine(TasksRoot, task.Path.TrimStart('\\')),
                    command);
            }
        }
    }

    /// <summary>
    /// Extracts the Exec-action command lines from a Task Scheduler XML definition. The
    /// schema uses a default namespace, so matching is by local element name. Invalid
    /// XML yields nothing (isolated, never throws).
    /// </summary>
    /// <remarks>
    /// <b>The arguments are the payload, and they used to be discarded.</b> An Exec action stores
    /// the interpreter in <c>&lt;Command&gt;</c> and what it is told to run in
    /// <c>&lt;Arguments&gt;</c>, so reading only the first reduces
    /// <c>rundll32.exe C:\Users\…\AppData\Roaming\evil.dll,Start</c> to <c>rundll32.exe</c> — a
    /// Microsoft-signed binary with a valid signature, and no trace anywhere in the report of the
    /// DLL it loads. Measured on a real desktop: <b>12 of the 15</b> autostart entries resolving to
    /// an interpreter were scheduled tasks, and every one of them carried an empty command line.
    /// The surface most used for modern persistence was the one reporting the least evidence.
    ///
    /// Pairing is done through each <c>Command</c> element's own parent rather than by matching
    /// <c>Exec</c> elements, so the flat descendant search that made this robust against unexpected
    /// nesting is preserved: a <c>Command</c> the schema puts somewhere unforeseen still yields its
    /// command, simply without arguments, instead of disappearing from the scan.
    ///
    /// The two are joined with a space into one command line because that is the string
    /// <see cref="CommandLine.ResolveExecutable"/> already parses — it takes the longest leading
    /// prefix that exists on disk, so a spaced or quoted program path still resolves and the
    /// arguments become inert trailing text rather than a second parsing rule to keep correct.
    /// </remarks>
    public static IReadOnlyList<string> ParseTaskCommands(string xml) =>
        TryParseTaskCommands(xml, out var commands) ? commands : [];

    internal static bool TryParseTaskCommands(string xml, out IReadOnlyList<string> commands) =>
        TryParseTaskCommands(xml, out commands, out _);

    internal static bool TryParseTaskCommands(
        string xml, out IReadOnlyList<string> commands, out int unresolvedComHandlers)
    {
        unresolvedComHandlers = 0;
        XDocument doc;
        try
        {
            doc = XDocument.Parse(xml);
        }
        catch (XmlException)
        {
            commands = [];
            return false;
        }
        var found = doc.Descendants()
            .Where(e => e.Name.LocalName == "Command")
            .Select(e => Join(e.Value.Trim(), SiblingArguments(e)))
            .Where(c => c.Length > 0)
            .ToList();

        // A ComHandler action runs code just as an Exec action does - it instantiates a CLSID and
        // calls into it - and reading only Exec meant such a task left the report entirely, without
        // even incrementing the unreadable count.
        //
        // Only a handler whose CLSID resolves to a file is emitted, because every entry in this
        // report is graded by the image model and a bare GUID has nothing to resolve. Windows ships
        // ComHandler tasks whose classes are not registered where a CLSID lookup can reach them, so
        // reporting the GUID itself would flag eight stock tasks as "no resolvable image" on every
        // machine. The unresolvable ones are counted instead - which is exactly the gap: they used
        // to vanish from the report without incrementing anything.
        unresolvedComHandlers = 0;
        foreach (var handler in doc.Descendants().Where(e => e.Name.LocalName == "ComHandler"))
        {
            var target = ComHandlerTarget(handler);
            if (target.Length > 0)
            {
                found.Add(target);
            }
            else
            {
                unresolvedComHandlers++;
            }
        }

        commands = found;
        return true;
    }

    /// <summary>
    /// The binary a <c>ComHandler</c> action loads, or empty when its CLSID names no file.
    /// </summary>
    private static string ComHandlerTarget(XElement handler)
    {
        var clsid = handler.Elements()
            .FirstOrDefault(child => child.Name.LocalName == "ClassId")?
            .Value
            .Trim();
        if (string.IsNullOrEmpty(clsid))
        {
            return string.Empty;
        }
        return ClsidResolver.ResolveInprocServer(clsid, RegistryView.Registry64)
            ?? ClsidResolver.ResolveInprocServer(clsid, RegistryView.Registry32)
            ?? string.Empty;
    }

    /// <summary>The <c>Arguments</c> value beside a given <c>Command</c>, or null when it has none.</summary>
    private static string? SiblingArguments(XElement command) =>
        command.Parent?
            .Elements()
            .FirstOrDefault(sibling => sibling.Name.LocalName == "Arguments")?
            .Value
            .Trim();

    private static string Join(string command, string? arguments) =>
        command.Length == 0 || string.IsNullOrEmpty(arguments)
            ? command
            : $"{command} {arguments}";

}

/// <summary>
/// AppInit_DLLs, DLLs that (when LoadAppInit_DLLs is enabled) are injected into
/// every user-mode process that loads user32.dll. A powerful, oft-abused vector;
/// any entry here is worth surfacing. Covers the 64- and 32-bit views.
/// </summary>
public sealed class AppInitDllsEnumerator : IAutostartEnumerator
{
    private const string Path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
    private static readonly char[] Separators = [',', ' '];

    public string Surface => "AppInit_DLLs";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path),
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry32, Path),
    };

    public IEnumerable<RawAutostart> Enumerate()
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var key = baseKey.OpenSubKey(Path);
            if (key?.GetValue("AppInit_DLLs") is not string raw || raw.Trim().Length == 0)
            {
                continue;
            }
            foreach (var dll in raw.Split(
                         Separators,
                         StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                yield return new RawAutostart(
                    AutostartVector.AppInitDll, "AppInit_DLLs", $"HKLM\\{Path} [{view}]", dll);
            }
        }
    }
}

/// <summary>
/// Active Setup StubPath commands, run once per user at first logon (and again when
/// a component's version bumps). A quiet, per-user persistence spot. Covers both
/// registry views.
/// </summary>
public sealed class ActiveSetupEnumerator : IAutostartEnumerator
{
    private const string Path = @"SOFTWARE\Microsoft\Active Setup\Installed Components";

    public string Surface => "Active Setup";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path, watchSubtree: true),
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry32, Path, watchSubtree: true),
    };

    public IEnumerable<RawAutostart> Enumerate()
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var root = baseKey.OpenSubKey(Path);
            if (root is null)
            {
                continue;
            }
            foreach (var component in root.GetSubKeyNames())
            {
                using var sub = root.OpenSubKey(component);
                if (sub?.GetValue("StubPath") is string stub && stub.Trim().Length > 0)
                {
                    yield return new RawAutostart(
                        AutostartVector.ActiveSetup, component,
                        $"HKLM\\{Path}\\{component} [StubPath, {view}]", stub);
                }
            }
        }
    }
}

/// <summary>
/// Session Manager BootExecute, native-mode commands run by smss.exe at boot,
/// before Win32 starts (default: "autocheck autochk *"). Anything appended here is a
/// very early, stealthy persistence vector.
/// </summary>
public sealed class BootExecuteEnumerator : IAutostartEnumerator
{
    private const string Path = @"SYSTEM\CurrentControlSet\Control\Session Manager";

    public string Surface => "BootExecute";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path),
    };

    public IEnumerable<RawAutostart> Enumerate()
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = baseKey.OpenSubKey(Path);
        if (key?.GetValue("BootExecute") is not string[] commands)
        {
            yield break;
        }
        foreach (var command in commands)
        {
            if (command.Trim().Length > 0)
            {
                yield return new RawAutostart(
                    AutostartVector.BootExecute, "BootExecute", $"HKLM\\{Path} [BootExecute]",
                    StripSessionManagerVerb(command));
            }
        }
    }

    /// <summary>
    /// Drops the Session Manager <c>autocheck</c> verb so the entry names the image smss.exe
    /// actually runs.
    /// </summary>
    /// <remarks>
    /// The stock Windows value is <c>autocheck autochk *</c>: <c>autocheck</c> is smss's verb, and
    /// <c>autochk.exe</c> is the native binary. Reading the raw value leading-token-first resolved
    /// <c>autocheck</c> to nothing, so the operating system's own default BootExecute entry was
    /// reported with no resolvable image on every machine — a permanent false positive on one of
    /// the highest-value persistence surfaces. Anything an attacker appends here keeps its own
    /// image name and is judged on it.
    /// </remarks>
    internal static string StripSessionManagerVerb(string command)
    {
        const string Verb = "autocheck ";
        var trimmed = command.TrimStart();
        return trimmed.StartsWith(Verb, StringComparison.OrdinalIgnoreCase)
            ? trimmed[Verb.Length..].TrimStart()
            : command;
    }
}

/// <summary>
/// AppCertDLLs, DLLs loaded into every process that calls CreateProcess/WinExec and
/// related APIs. A powerful, oft-abused injection/persistence vector (MITRE
/// T1546.009). Values are DLL paths.
/// </summary>
public sealed class AppCertDllsEnumerator : IAutostartEnumerator
{
    private const string Path = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls";

    public string Surface => "AppCertDLLs";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path),
    };

    public IEnumerable<RawAutostart> Enumerate()
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = baseKey.OpenSubKey(Path);
        if (key is null)
        {
            yield break;
        }
        foreach (var name in key.GetValueNames())
        {
            if (key.GetValue(name) is string dll && dll.Trim().Length > 0)
            {
                yield return new RawAutostart(AutostartVector.AppCertDll, name, $"HKLM\\{Path}", dll);
            }
        }
    }
}

/// <summary>
/// W32Time time providers, DLLs loaded by the Windows Time service. A rogue provider
/// DllName runs inside the time service; a documented, low-noise persistence spot.
/// </summary>
public sealed class TimeProviderEnumerator : IAutostartEnumerator
{
    private const string Path = @"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders";

    public string Surface => "Time providers";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path, watchSubtree: true),
    };

    public IEnumerable<RawAutostart> Enumerate()
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var root = baseKey.OpenSubKey(Path);
        if (root is null)
        {
            yield break;
        }
        foreach (var provider in root.GetSubKeyNames())
        {
            using var sub = root.OpenSubKey(provider);
            if (sub?.GetValue("DllName") is string dll && dll.Trim().Length > 0)
            {
                yield return new RawAutostart(
                    AutostartVector.TimeProvider, provider, $"HKLM\\{Path}\\{provider} [DllName]", dll);
            }
        }
    }
}

/// <summary>
/// The screensaver executable (SCRNSAVE.EXE), a .scr is just a PE that Windows runs
/// on idle, so pointing it at a payload is a classic, low-noise persistence trick
/// (MITRE T1546.002). Read per-user from HKCU\Control Panel\Desktop and its Group
/// Policy twin, both of which can force a screensaver on.
/// </summary>
public sealed class ScreensaverEnumerator : IAutostartEnumerator
{
    private const string Value = "SCRNSAVE.EXE";
    private static readonly string[] Paths =
    {
        @"Control Panel\Desktop",
        @"Software\Policies\Microsoft\Windows\Control Panel\Desktop",
    };

    public string Surface => "Screensaver";

    public IEnumerable<RawAutostart> Enumerate()
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
        foreach (var path in Paths)
        {
            using var key = baseKey.OpenSubKey(path);
            if (key?.GetValue(Value) is string scr && scr.Trim().Length > 0)
            {
                yield return new RawAutostart(
                    AutostartVector.Screensaver, Value, $"HKCU\\{path} [{Value}]", scr);
            }
        }
    }
}

/// <summary>
/// Per-user COM server registrations (HKCU\Software\Classes\CLSID\{clsid}\
/// InprocServer32). A user-level CLSID that shadows a system one lets malware load
/// its DLL whenever that COM object is instantiated, COM hijacking (MITRE
/// T1546.015). HKCU is scanned (not the thousands of legitimate HKLM system CLSIDs),
/// which is where the high-signal per-user hijacks live.
/// </summary>
public sealed class ComHijackEnumerator : IAutostartEnumerator
{
    private const string Path = @"SOFTWARE\Classes\CLSID";

    public string Surface => "COM (HKCU CLSID)";

    /// <summary>
    /// The server keys a CLSID registration can name, in the order COM consults them.
    /// </summary>
    /// <remarks>
    /// Only <c>InprocServer32</c> was read, which is three of the four ways a CLSID can point at
    /// code and none of the fifth. <c>LocalServer32</c> names an executable rather than a DLL, and
    /// <c>TreatAs</c> is the sharpest of the lot: it redirects the class to a completely different
    /// CLSID, so a hijack written that way left no trace anywhere in the report - the entry
    /// WinSight showed was the legitimate server of a class that COM no longer instantiates.
    /// </remarks>
    private static readonly (string Key, string? Value)[] ServerKeys =
    [
        ("InprocServer32", null),
        ("InprocServer", null),
        ("InprocHandler32", null),
        ("LocalServer32", null),
        ("TreatAs", null),
    ];

    public IEnumerable<RawAutostart> Enumerate()
    {
        // Both views: a 32-bit COM server registered under the WOW6432Node twin is loaded into
        // every 32-bit host that instantiates the class, and was previously invisible.
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view);
            using var root = baseKey.OpenSubKey(Path);
            if (root is null)
            {
                continue;
            }
            foreach (var clsid in root.GetSubKeyNames())
            {
                foreach (var entry in ServerEntries(root, clsid, view))
                {
                    yield return entry;
                }
            }
        }
    }

    private static List<RawAutostart> ServerEntries(RegistryKey root, string clsid, RegistryView view)
    {
        var entries = new List<RawAutostart>();
        foreach (var (key, _) in ServerKeys)
        {
            try
            {
                using var server = root.OpenSubKey($@"{clsid}\{key}");
                if (server?.GetValue(null) is string target && target.Trim().Length > 0)
                {
                    // A TreatAs value is a CLSID, not a path: report the binary the redirection
                    // ends at, so the signature model sees a file. Reporting the raw GUID made the
                    // legitimate OLE mapping Windows ships read as "no resolvable image" on every
                    // machine, while saying nothing about the code the class actually loads - which
                    // is the entire point of following a TreatAs.
                    var command = key == "TreatAs"
                        ? ClsidResolver.ResolveInprocServer(target.Trim(), view) ?? target
                        : target;
                    entries.Add(new RawAutostart(
                        AutostartVector.ComHijack, $"{clsid} [{key}]",
                        $"HKCU\\{RegistryViews.Describe(Path, view)}\\{clsid}\\{key}", command));
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
            {
                // Unreadable CLSID key, skip.
            }
        }
        return entries;
    }
}

/// <summary>
/// Print monitors, DLLs loaded by the print spooler service (spoolsv). A rogue
/// monitor Driver DLL runs as SYSTEM at boot; a documented persistence vector.
/// </summary>
public sealed class PrintMonitorEnumerator : IAutostartEnumerator
{
    private const string Path = @"SYSTEM\CurrentControlSet\Control\Print\Monitors";

    public string Surface => "Print monitors";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path, watchSubtree: true),
    };

    public IEnumerable<RawAutostart> Enumerate()
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var root = baseKey.OpenSubKey(Path);
        if (root is null)
        {
            yield break;
        }
        foreach (var monitor in root.GetSubKeyNames())
        {
            using var sub = root.OpenSubKey(monitor);
            if (sub?.GetValue("Driver") is string driver && driver.Trim().Length > 0)
            {
                yield return new RawAutostart(
                    AutostartVector.PrintMonitor, monitor, $"HKLM\\{Path}\\{monitor} [Driver]", driver);
            }
        }
    }
}

/// <summary>
/// Netsh helper DLLs, loaded when netsh.exe runs. A malicious helper registered
/// here executes whenever netsh is invoked; a stealthy persistence spot.
/// </summary>
public sealed class NetshHelperEnumerator : IAutostartEnumerator
{
    private const string Path = @"SOFTWARE\Microsoft\NetSh";

    public string Surface => "Netsh helpers";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path),
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry32, Path),
    };

    public IEnumerable<RawAutostart> Enumerate()
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var key = baseKey.OpenSubKey(Path);
            if (key is null)
            {
                continue;
            }
            foreach (var name in key.GetValueNames())
            {
                if (key.GetValue(name) is string dll && dll.Trim().Length > 0)
                {
                    yield return new RawAutostart(
                        AutostartVector.NetshHelper, name, $"HKLM\\{Path} [{view}]", dll);
                }
            }
        }
    }
}

/// <summary>
/// LSA Security/Authentication/Notification packages, DLLs loaded into the highly
/// privileged LSASS process. A malicious Security Support Provider or password-filter
/// DLL registered here is a classic, powerful persistence + credential-theft vector.
/// Values are REG_MULTI_SZ module base names (resolved against System32).
/// </summary>
public sealed class LsaPackagesEnumerator : IAutostartEnumerator
{
    private const string Path = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private static readonly string[] Values =
        { "Security Packages", "Authentication Packages", "Notification Packages" };

    public string Surface => "LSA packages";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path),
    };

    public IEnumerable<RawAutostart> Enumerate()
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = baseKey.OpenSubKey(Path);
        if (key is null)
        {
            yield break;
        }
        foreach (var value in Values)
        {
            if (key.GetValue(value) is not string[] packages)
            {
                continue;
            }
            foreach (var raw in packages)
            {
                var pkg = raw.Trim();
                if (pkg.Length == 0 || pkg == "\"\"")
                {
                    continue;
                }
                yield return new RawAutostart(
                    AutostartVector.LsaPackage, pkg, $"HKLM\\{Path} [{value}]", pkg);
            }
        }
    }
}

/// <summary>
/// SilentProcessExit MonitorProcess hijacks (MITRE T1546.012): when IFEO GlobalFlag
/// enables silent-exit monitoring for a target executable, the MonitorProcess
/// registered here is launched every time that target exits, a quiet companion to
/// the IFEO Debugger hijack. Any MonitorProcess entry is reported.
/// </summary>
public sealed class SilentProcessExitEnumerator : IAutostartEnumerator
{
    private const string Path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";

    public string Surface => "SilentProcessExit monitors";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path, watchSubtree: true),
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry32, Path, watchSubtree: true),
    };

    /// <summary>
    /// Both views: SilentProcessExit sits in the same redirected part of the registry as IFEO, and
    /// a monitor registered for a 32-bit target lives in the WOW6432Node twin.
    /// </summary>
    public IEnumerable<RawAutostart> Enumerate()
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var root = baseKey.OpenSubKey(Path);
            if (root is null)
            {
                continue;
            }
            foreach (var target in root.GetSubKeyNames())
            {
                RawAutostart? entry = null;
                try
                {
                    using var sub = root.OpenSubKey(target);
                    if (sub?.GetValue("MonitorProcess") is string monitor && monitor.Trim().Length > 0)
                    {
                        entry = new RawAutostart(
                            AutostartVector.SilentProcessExit, target,
                            $"HKLM\\{RegistryViews.Describe(Path, view)}\\{target} [MonitorProcess]", monitor);
                    }
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
                {
                    // Unreadable target key, skip.
                }
                if (entry is { } e)
                {
                    yield return e;
                }
            }
        }
    }
}

/// <summary>
/// Image File Execution Options "Debugger" hijacks: a Debugger value on a target
/// executable makes Windows launch the debugger INSTEAD of the target, a classic
/// persistence/hijack (e.g. hijacking sethc.exe). Each Debugger entry is reported.
/// </summary>
public sealed class ImageHijackEnumerator : IAutostartEnumerator
{
    private const string Path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

    // Per-executable Debugger / GlobalFlag hijacks live in subkeys under this root.
    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path, watchSubtree: true),
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry32, Path, watchSubtree: true),
    };

    public string Surface => "IFEO debuggers";

    /// <summary>
    /// Both registry views, because IFEO is redirected and the two halves govern different
    /// processes.
    /// </summary>
    /// <remarks>
    /// A WOW64 process reads its execution options through the 32-bit ntdll, which is redirected to
    /// <c>SOFTWARE\WOW6432Node\...\Image File Execution Options</c> - the same reason Microsoft's
    /// own guidance for attaching a debugger to a 32-bit application says to write there. Reading
    /// only the 64-bit view left a Debugger value that hijacks every 32-bit process on the machine
    /// completely invisible, on the surface whose whole purpose is to catch that.
    /// </remarks>
    public IEnumerable<RawAutostart> Enumerate()
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var root = baseKey.OpenSubKey(Path);
            if (root is null)
            {
                continue;
            }
            foreach (var target in root.GetSubKeyNames())
            {
                using var sub = root.OpenSubKey(target);
                if (sub?.GetValue("Debugger") is string debugger && debugger.Trim().Length > 0)
                {
                    yield return new RawAutostart(
                        AutostartVector.ImageHijack, target,
                        $"HKLM\\{RegistryViews.Describe(Path, view)}\\{target} [Debugger]", debugger);
                }
            }
        }
    }
}
