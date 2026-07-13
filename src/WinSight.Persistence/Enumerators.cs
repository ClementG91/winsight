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

    // Real task definitions are a few KB; a huge file planted under \Tasks must not
    // be read whole into memory (resource-exhaustion resistance).
    private const long MaxTaskFileBytes = 1024 * 1024;

    public IEnumerable<RawAutostart> Enumerate()
    {
        foreach (var file in SafeFiles(TasksRoot))
        {
            string xml;
            try
            {
                if (new FileInfo(file).Length > MaxTaskFileBytes)
                {
                    continue;
                }
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
/// Active Setup StubPath commands — run once per user at first logon (and again when
/// a component's version bumps). A quiet, per-user persistence spot. Covers both
/// registry views.
/// </summary>
public sealed class ActiveSetupEnumerator : IAutostartEnumerator
{
    private const string Path = @"SOFTWARE\Microsoft\Active Setup\Installed Components";

    public string Surface => "Active Setup";

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
/// Session Manager BootExecute — native-mode commands run by smss.exe at boot,
/// before Win32 starts (default: "autocheck autochk *"). Anything appended here is a
/// very early, stealthy persistence vector.
/// </summary>
public sealed class BootExecuteEnumerator : IAutostartEnumerator
{
    private const string Path = @"SYSTEM\CurrentControlSet\Control\Session Manager";

    public string Surface => "BootExecute";

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
                    AutostartVector.BootExecute, "BootExecute", $"HKLM\\{Path} [BootExecute]", command);
            }
        }
    }
}

/// <summary>
/// AppCertDLLs — DLLs loaded into every process that calls CreateProcess/WinExec and
/// related APIs. A powerful, oft-abused injection/persistence vector (MITRE
/// T1546.009). Values are DLL paths.
/// </summary>
public sealed class AppCertDllsEnumerator : IAutostartEnumerator
{
    private const string Path = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls";

    public string Surface => "AppCertDLLs";

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
/// W32Time time providers — DLLs loaded by the Windows Time service. A rogue provider
/// DllName runs inside the time service; a documented, low-noise persistence spot.
/// </summary>
public sealed class TimeProviderEnumerator : IAutostartEnumerator
{
    private const string Path = @"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders";

    public string Surface => "Time providers";

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
/// The screensaver executable (SCRNSAVE.EXE) — a .scr is just a PE that Windows runs
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
/// its DLL whenever that COM object is instantiated — COM hijacking (MITRE
/// T1546.015). HKCU is scanned (not the thousands of legitimate HKLM system CLSIDs),
/// which is where the high-signal per-user hijacks live.
/// </summary>
public sealed class ComHijackEnumerator : IAutostartEnumerator
{
    private const string Path = @"SOFTWARE\Classes\CLSID";

    public string Surface => "COM (HKCU CLSID)";

    public IEnumerable<RawAutostart> Enumerate()
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
        using var root = baseKey.OpenSubKey(Path);
        if (root is null)
        {
            yield break;
        }
        foreach (var clsid in root.GetSubKeyNames())
        {
            RawAutostart? entry = null;
            try
            {
                using var server = root.OpenSubKey($@"{clsid}\InprocServer32");
                if (server?.GetValue(null) is string dll && dll.Trim().Length > 0)
                {
                    entry = new RawAutostart(
                        AutostartVector.ComHijack, clsid,
                        $"HKCU\\{Path}\\{clsid}\\InprocServer32", dll);
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
            {
                // Unreadable CLSID key — skip.
            }
            if (entry is { } e)
            {
                yield return e;
            }
        }
    }
}

/// <summary>
/// Print monitors — DLLs loaded by the print spooler service (spoolsv). A rogue
/// monitor Driver DLL runs as SYSTEM at boot; a documented persistence vector.
/// </summary>
public sealed class PrintMonitorEnumerator : IAutostartEnumerator
{
    private const string Path = @"SYSTEM\CurrentControlSet\Control\Print\Monitors";

    public string Surface => "Print monitors";

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
/// Netsh helper DLLs — loaded when netsh.exe runs. A malicious helper registered
/// here executes whenever netsh is invoked; a stealthy persistence spot.
/// </summary>
public sealed class NetshHelperEnumerator : IAutostartEnumerator
{
    private const string Path = @"SOFTWARE\Microsoft\NetSh";

    public string Surface => "Netsh helpers";

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
/// LSA Security/Authentication/Notification packages — DLLs loaded into the highly
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
