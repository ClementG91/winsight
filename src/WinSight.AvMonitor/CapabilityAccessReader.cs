using Microsoft.Win32;

namespace WinSight.AvMonitor;

/// <summary>
/// Reads the Windows CapabilityAccessManager ConsentStore to report which apps have
/// used the webcam/microphone and which are using them right now. This is the
/// registry-backed (no-driver) core of the OverSight-class monitor; ETW-based
/// real-time alerting builds on top later.
///
/// Per capability, Windows records each app under
/// ...\CapabilityAccessManager\ConsentStore\{webcam|microphone}\ with QWORD
/// LastUsedTimeStart / LastUsedTimeStop FILETIMEs. A start with a zero stop means the
/// device is live. Desktop apps live under a NonPackaged subkey, keyed by their exe
/// path with '#' substituted for '\'.
/// </summary>
public sealed class CapabilityAccessReader
{
    private const string Base =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

    /// <summary>Reads recorded webcam + microphone usage across HKCU and HKLM.</summary>
    public IReadOnlyList<DeviceUsage> Read()
    {
        var results = new List<DeviceUsage>();
        foreach (var (kind, capability) in new[]
                 {
                     (DeviceKind.Webcam, "webcam"),
                     (DeviceKind.Microphone, "microphone"),
                 })
        {
            foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
            {
                ReadCapability(hive, capability, kind, results);
            }
        }
        return results;
    }

    private static void ReadCapability(
        RegistryHive hive, string capability, DeviceKind kind, List<DeviceUsage> results)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var capKey = baseKey.OpenSubKey($@"{Base}\{capability}");
            if (capKey is null)
            {
                return;
            }
            foreach (var appName in capKey.GetSubKeyNames())
            {
                if (appName.Equals("NonPackaged", StringComparison.OrdinalIgnoreCase))
                {
                    using var nonPackaged = capKey.OpenSubKey(appName);
                    foreach (var exeKey in nonPackaged?.GetSubKeyNames() ?? Array.Empty<string>())
                    {
                        using var appKey = nonPackaged!.OpenSubKey(exeKey);
                        AddUsage(appKey, DecodeExePath(exeKey), packaged: false, kind, results);
                    }
                }
                else
                {
                    using var appKey = capKey.OpenSubKey(appName);
                    AddUsage(appKey, appName, packaged: true, kind, results);
                }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            // A hive/capability we cannot read is simply skipped.
        }
    }

    private static void AddUsage(
        RegistryKey? appKey, string app, bool packaged, DeviceKind kind, List<DeviceUsage> results)
    {
        if (appKey is null)
        {
            return;
        }
        var start = ReadFileTime(appKey, "LastUsedTimeStart");
        var stop = ReadFileTime(appKey, "LastUsedTimeStop");
        if (start is null && stop is null)
        {
            return; // no recorded usage
        }
        results.Add(new DeviceUsage(kind, app, packaged, start, stop, IsActive(start, stop)));
    }

    private static DateTime? ReadFileTime(RegistryKey key, string valueName) =>
        key.GetValue(valueName) is long ft && ft > 0 ? DateTime.FromFileTimeUtc(ft) : null;

    /// <summary>The device is in use now when a start time is set but no stop time is.</summary>
    public static bool IsActive(DateTime? start, DateTime? stop) => start is not null && stop is null;

    /// <summary>Decodes a NonPackaged app key (exe path with '#' for '\') back to a path.</summary>
    public static string DecodeExePath(string keyName) => keyName.Replace('#', '\\');
}
