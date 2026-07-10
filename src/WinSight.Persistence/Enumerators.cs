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
