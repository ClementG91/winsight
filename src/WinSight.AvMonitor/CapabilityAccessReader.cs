using Microsoft.Win32;
using WinSight.Core;

namespace WinSight.AvMonitor;

/// <summary>
/// The source of capture-device usage, behind an interface so the alerting path above it can be
/// tested without a webcam.
/// </summary>
/// <remarks>
/// This exists because the concrete reader is registry- and hardware-bound: on a machine with no
/// webcam — including every CI runner — nothing can ever produce a camera transition, so an
/// end-to-end test of "device turns on, operator gets told" was impossible to write. For a security
/// product, an alerting path that cannot be exercised is a defect in itself.
/// </remarks>
public interface ICapabilityAccessReader
{
    /// <summary>Recorded webcam and microphone usage, including what is live right now.</summary>
    IReadOnlyList<DeviceUsage> Read();
}

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
public sealed class CapabilityAccessReader : ICapabilityAccessReader
{
    private const string DefaultBasePath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

    private readonly string _basePath;

    /// <summary>Creates the production reader over the Windows ConsentStore.</summary>
    public CapabilityAccessReader() : this(DefaultBasePath)
    {
    }

    /// <summary>Creates a reader over an isolated registry path for deterministic tests.</summary>
    internal CapabilityAccessReader(string basePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(basePath);
        _basePath = basePath;
    }

    /// <summary>Reads recorded webcam + microphone usage across HKCU and HKLM.</summary>
    public IReadOnlyList<DeviceUsage> Read() => ReadWithCoverage().Items;

    /// <summary>Reads usage and reports every capability/hive surface that could not be read.</summary>
    public AcquisitionSnapshot<DeviceUsage> ReadWithCoverage()
    {
        var results = new List<DeviceUsage>();
        var unreadableSources = 0;
        var unreadableItems = 0;
        foreach (var (kind, capability) in new[]
                 {
                     (DeviceKind.Webcam, "webcam"),
                     (DeviceKind.Microphone, "microphone"),
                 })
        {
            foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
            {
                var (readable, itemGaps) = ReadCapability(hive, capability, kind, results);
                if (!readable)
                {
                    unreadableSources++;
                }
                unreadableItems += itemGaps;
            }
        }
        return new AcquisitionSnapshot<DeviceUsage>(results, unreadableSources, unreadableItems);
    }

    private (bool SourceReadable, int UnreadableItems) ReadCapability(
        RegistryHive hive, string capability, DeviceKind kind, List<DeviceUsage> results)
    {
        var unreadableItems = 0;
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var capKey = baseKey.OpenSubKey($@"{_basePath}\{capability}");
            if (capKey is null)
            {
                return (true, 0);
            }
            foreach (var appName in capKey.GetSubKeyNames())
            {
                if (appName.Equals("NonPackaged", StringComparison.OrdinalIgnoreCase))
                {
                    using var nonPackaged = capKey.OpenSubKey(appName);
                    if (nonPackaged is null)
                    {
                        unreadableItems++;
                        continue;
                    }
                    foreach (var exeKey in nonPackaged.GetSubKeyNames())
                    {
                        using var appKey = nonPackaged.OpenSubKey(exeKey);
                        if (!TryAddUsage(appKey, DecodeExePath(exeKey), packaged: false, kind, results))
                        {
                            unreadableItems++;
                        }
                    }
                }
                else
                {
                    using var appKey = capKey.OpenSubKey(appName);
                    if (!TryAddUsage(appKey, appName, packaged: true, kind, results))
                    {
                        unreadableItems++;
                    }
                }
            }
            return (true, unreadableItems);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or IOException)
        {
            return (false, unreadableItems);
        }
    }

    private static bool TryAddUsage(
        RegistryKey? appKey, string app, bool packaged, DeviceKind kind, List<DeviceUsage> results)
    {
        if (appKey is null)
        {
            return false;
        }
        try
        {
            var start = ReadFileTime(appKey, "LastUsedTimeStart");
            var stop = ReadFileTime(appKey, "LastUsedTimeStop");
            if (start is null && stop is null)
            {
                return true; // no recorded usage
            }
            results.Add(new DeviceUsage(kind, app, packaged, start, stop, IsActive(start, stop)));
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or IOException
                                     or ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    private static DateTime? ReadFileTime(RegistryKey key, string valueName) =>
        key.GetValue(valueName) is long ft && ft > 0 ? DateTime.FromFileTimeUtc(ft) : null;

    /// <summary>The device is in use now when a start time is set but no stop time is.</summary>
    public static bool IsActive(DateTime? start, DateTime? stop) => start is not null && stop is null;

    /// <summary>Decodes a NonPackaged app key (exe path with '#' for '\') back to a path.</summary>
    public static string DecodeExePath(string keyName) => keyName.Replace('#', '\\');
}
