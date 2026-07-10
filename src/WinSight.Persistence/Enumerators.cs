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
}

/// <summary>
/// The classic Run/RunOnce registry autostart keys, across HKLM+HKCU and both the
/// 64-bit and 32-bit (WOW6432Node) views — a favourite malware persistence spot.
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
            var location = $"{HiveName(hive)}\\{sub} [{view}]";
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
/// the service control database in the registry, keyed by ImagePath.
/// </summary>
public sealed class ServiceEnumerator : IAutostartEnumerator
{
    private const string Root = @"SYSTEM\CurrentControlSet\Services";

    public string Surface => "Services & drivers";

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
            RawAutostart? entry = null;
            try
            {
                using var svc = services.OpenSubKey(name);
                // Start: 0=boot 1=system 2=auto 3=manual 4=disabled. Only auto-starting.
                if (svc?.GetValue("ImagePath") is string image && image.Length > 0 &&
                    svc.GetValue("Start") is int start && start <= 2)
                {
                    entry = new RawAutostart(
                        AutostartVector.Service, name, $"HKLM\\{Root}\\{name}", image);
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
            {
                // Skip service keys we cannot read.
            }

            if (entry is { } e)
            {
                yield return e;
            }
        }
    }
}

/// <summary>
/// The Winlogon Shell/Userinit hooks — the processes the OS launches at logon.
/// Defaults are explorer.exe and userinit.exe; malware appends its own comma-
/// separated payload here, so any EXTRA command beyond the default is notable.
/// </summary>
public sealed class WinlogonEnumerator : IAutostartEnumerator
{
    private const string Path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private static readonly string[] Values = { "Shell", "Userinit" };

    public string Surface => "Winlogon Shell/Userinit";

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
            if (key.GetValue(value) is not string raw)
            {
                continue;
            }
            foreach (var command in SplitCommands(raw))
            {
                yield return new RawAutostart(
                    AutostartVector.Winlogon, value, $"HKLM\\{Path} [{value}]", command);
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
/// Scheduled Tasks, read by parsing the task definition XML files under
/// %SystemRoot%\System32\Tasks (no Task Scheduler COM dependency). Each task's
/// Exec action Command is an autostart command. A favourite modern persistence spot.
/// </summary>
public sealed class ScheduledTaskEnumerator : IAutostartEnumerator
{
    private static readonly string TasksRoot =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");

    public string Surface => "Scheduled Tasks";

    public IEnumerable<RawAutostart> Enumerate()
    {
        foreach (var file in SafeFiles(TasksRoot))
        {
            string xml;
            try
            {
                xml = File.ReadAllText(file);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            var name = Path.GetRelativePath(TasksRoot, file);
            foreach (var command in ParseTaskCommands(xml))
            {
                yield return new RawAutostart(AutostartVector.ScheduledTask, name, file, command);
            }
        }
    }

    /// <summary>
    /// Extracts the Exec-action commands from a Task Scheduler XML definition. The
    /// schema uses a default namespace, so matching is by local element name. Invalid
    /// XML yields nothing (isolated, never throws).
    /// </summary>
    public static IReadOnlyList<string> ParseTaskCommands(string xml)
    {
        XDocument doc;
        try
        {
            doc = XDocument.Parse(xml);
        }
        catch (XmlException)
        {
            return Array.Empty<string>();
        }
        return doc.Descendants()
            .Where(e => e.Name.LocalName == "Command")
            .Select(e => e.Value.Trim())
            .Where(c => c.Length > 0)
            .ToList();
    }

    private static IReadOnlyList<string> SafeFiles(string root)
    {
        try
        {
            return Directory.Exists(root)
                ? Directory.GetFiles(root, "*", SearchOption.AllDirectories)
                : Array.Empty<string>();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Array.Empty<string>();
        }
    }
}

/// <summary>
/// AppInit_DLLs — DLLs that (when LoadAppInit_DLLs is enabled) are injected into
/// every user-mode process that loads user32.dll. A powerful, oft-abused vector;
/// any entry here is worth surfacing. Covers the 64- and 32-bit views.
/// </summary>
public sealed class AppInitDllsEnumerator : IAutostartEnumerator
{
    private const string Path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";

    public string Surface => "AppInit_DLLs";

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
                         new[] { ',', ' ' },
                         StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                yield return new RawAutostart(
                    AutostartVector.AppInitDll, "AppInit_DLLs", $"HKLM\\{Path} [{view}]", dll);
            }
        }
    }
}

/// <summary>
/// Image File Execution Options "Debugger" hijacks: a Debugger value on a target
/// executable makes Windows launch the debugger INSTEAD of the target — a classic
/// persistence/hijack (e.g. hijacking sethc.exe). Each Debugger entry is reported.
/// </summary>
public sealed class ImageHijackEnumerator : IAutostartEnumerator
{
    private const string Path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

    public string Surface => "IFEO debuggers";

    public IEnumerable<RawAutostart> Enumerate()
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var root = baseKey.OpenSubKey(Path);
        if (root is null)
        {
            yield break;
        }
        foreach (var target in root.GetSubKeyNames())
        {
            using var sub = root.OpenSubKey(target);
            if (sub?.GetValue("Debugger") is string debugger && debugger.Trim().Length > 0)
            {
                yield return new RawAutostart(
                    AutostartVector.ImageHijack, target,
                    $"HKLM\\{Path}\\{target} [Debugger]", debugger);
            }
        }
    }
}
