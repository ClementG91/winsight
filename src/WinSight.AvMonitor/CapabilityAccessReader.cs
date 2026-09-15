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
    /// <summary>Usage plus unreadable surfaces/items; failures must not look like an empty snapshot.</summary>
    AcquisitionSnapshot<DeviceUsage> ReadWithCoverage();

    /// <summary>
    /// Usage with its store of origin and the exact parts that could not be read. Readers that cannot
    /// attribute their gaps keep the default, which the monitor treats conservatively.
    /// </summary>
    CapabilityAccessSnapshot ReadWithProvenance() => CapabilityAccessSnapshot.FromCoverage(ReadWithCoverage());
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
    public IReadOnlyList<DeviceUsage> Read() => ReadWithProvenance().Items;

    /// <summary>Reads usage and reports every capability/hive surface that could not be read.</summary>
    public AcquisitionSnapshot<DeviceUsage> ReadWithCoverage() => ReadWithProvenance().ToCoverage();

    /// <summary>Reads usage tagged with its store, and every unreadable part by scope.</summary>
    public CapabilityAccessSnapshot ReadWithProvenance()
    {
        var results = new List<DeviceUsage>();
        var gaps = new List<CapabilityGap>();
        foreach (var (kind, capability) in new[]
                 {
                     (DeviceKind.Webcam, "webcam"),
                     (DeviceKind.Microphone, "microphone"),
                 })
        {
            foreach (var (hive, store) in new[]
                     {
                         (RegistryHive.CurrentUser, CapabilityStore.CurrentUser),
                         (RegistryHive.LocalMachine, CapabilityStore.LocalMachine),
                     })
            {
                ReadCapability(hive, store, capability, kind, results, gaps);
            }
        }
        return new CapabilityAccessSnapshot(results, gaps);
    }

    private void ReadCapability(
        RegistryHive hive, CapabilityStore store, string capability, DeviceKind kind,
        List<DeviceUsage> results, List<CapabilityGap> gaps)
    {
        // Items are staged so a failure part-way through a store is reported as the whole store
        // being unreadable, never as a clean partial list.
        var staged = new List<DeviceUsage>();
        var stagedGaps = new List<CapabilityGap>();
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var capKey = baseKey.OpenSubKey($@"{_basePath}\{capability}");
            if (capKey is null)
            {
                return;
            }
            foreach (var appName in capKey.GetSubKeyNames())
            {
                if (appName.Equals("NonPackaged", StringComparison.OrdinalIgnoreCase))
                {
                    RegistryKey? nonPackaged;
                    string[] exeKeys;
                    try
                    {
                        nonPackaged = capKey.OpenSubKey(appName);
                        exeKeys = nonPackaged?.GetSubKeyNames() ?? [];
                    }
                    catch (Exception ex) when (IsReadFailure(ex))
                    {
                        stagedGaps.Add(new CapabilityGap(kind, store, Packaged: false));
                        continue;
                    }
                    if (nonPackaged is null)
                    {
                        stagedGaps.Add(new CapabilityGap(kind, store, Packaged: false));
                        continue;
                    }
                    using (nonPackaged)
                    {
                        foreach (var exeKey in exeKeys)
                        {
                            var app = DecodeExePath(exeKey);
                            if (!TryAddUsage(nonPackaged, exeKey, app, packaged: false, kind, store, staged))
                            {
                                stagedGaps.Add(new CapabilityGap(kind, store, app, Packaged: false));
                            }
                        }
                    }
                }
                else if (!TryAddUsage(capKey, appName, appName, packaged: true, kind, store, staged))
                {
                    stagedGaps.Add(new CapabilityGap(kind, store, appName, Packaged: true));
                }
            }
            results.AddRange(staged);
            gaps.AddRange(stagedGaps);
        }
        catch (Exception ex) when (IsReadFailure(ex))
        {
            gaps.Add(new CapabilityGap(kind, store));
        }
    }

    private static bool IsReadFailure(Exception ex) =>
        ex is UnauthorizedAccessException or System.Security.SecurityException or IOException;

    private static bool TryAddUsage(
        RegistryKey parent, string keyName, string app, bool packaged, DeviceKind kind,
        CapabilityStore store, List<DeviceUsage> results)
    {
        try
        {
            using var appKey = parent.OpenSubKey(keyName);
            if (appKey is null)
            {
                return false;
            }
            var start = ReadFileTime(appKey, "LastUsedTimeStart");
            var stop = ReadFileTime(appKey, "LastUsedTimeStop");
            if (start is null && stop is null)
            {
                return true; // no recorded usage
            }
            results.Add(new DeviceUsage(kind, app, packaged, start, stop, IsActive(start, stop)) { Store = store });
            return true;
        }
        catch (Exception ex) when (IsReadFailure(ex) || ex is ArgumentOutOfRangeException)
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
