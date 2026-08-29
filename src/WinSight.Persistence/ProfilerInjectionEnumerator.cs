using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// .NET profiler injection: a DLL the CLR loads into a managed process because the environment or
/// the registry told it to.
/// </summary>
/// <remarks>
/// <b>What this catches.</b> The CLR loads an arbitrary DLL at startup when
/// <c>COR_ENABLE_PROFILING=1</c> and a profiler is named - by CLSID in <c>COR_PROFILER</c>, or
/// directly by path in <c>COR_PROFILER_PATH</c>. Nothing about the DLL needs to be a real profiler.
/// It is a supported, documented loading mechanism, which is precisely why it is used as one
/// (ATT&amp;CK T1574.012): the code runs inside a legitimate signed process, and the only trace is a
/// registry value or an environment variable.
///
/// <b>Why the registry and not the environment block.</b> A variable set in a process is gone when
/// the process ends; persistence needs it to survive a reboot, and on Windows that means one of
/// three registry locations. All three are read here:
///
/// <list type="bullet">
/// <item>The machine-wide environment, which every process created afterwards inherits.</item>
/// <item>The user's environment, which needs no elevation at all - the quiet variant.</item>
/// <item>A service's own <c>Environment</c> value, which the SCM applies to that service alone.
/// That is the targeted variant: it puts a DLL inside one chosen service, usually one running as
/// SYSTEM, and touches nothing any other process would ever read.</item>
/// </list>
///
/// <b>What is reported.</b> The DLL, when a path is named. When only a CLSID is given, the CLSID is
/// resolved through the same COM registration the COM-hijack surface already reads, so the entry
/// names a file rather than a GUID. A profiler enabled with no resolvable image is still reported -
/// the registration is the finding, and an unresolvable one is if anything more interesting.
/// </remarks>
public sealed class ProfilerInjectionEnumerator : IAutostartEnumerator
{
    private const string MachineEnvironment =
        @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
    private const string UserEnvironment = "Environment";
    private const string Services = @"SYSTEM\CurrentControlSet\Services";

    private const string Enable = "COR_ENABLE_PROFILING";
    private const string Profiler = "COR_PROFILER";
    private const string ProfilerPath = "COR_PROFILER_PATH";

    private int _unreadableLocations;

    public string Surface => ".NET profiler injection";

    public int UnreadableLocations => _unreadableLocations;

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } =
    [
        PersistenceWatchTarget.Registry(
            RegistryHive.LocalMachine, RegistryView.Registry64, MachineEnvironment),
        PersistenceWatchTarget.Registry(
            RegistryHive.CurrentUser, RegistryView.Registry64, UserEnvironment),
    ];

    public IEnumerable<RawAutostart> Enumerate()
    {
        _unreadableLocations = 0;
        var entries = new List<RawAutostart>();
        ReadEnvironmentKey(entries, RegistryHive.LocalMachine, MachineEnvironment, "HKLM");
        ReadEnvironmentKey(entries, RegistryHive.CurrentUser, UserEnvironment, "HKCU");
        ReadServiceEnvironments(entries);
        return entries;
    }

    /// <summary>
    /// One environment block: machine-wide or the user's own.
    /// </summary>
    private void ReadEnvironmentKey(
        List<RawAutostart> entries, RegistryHive hive, string path, string hiveName)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(path);
            if (key is null)
            {
                return;
            }
            Add(entries,
                enabled: key.GetValue(Enable) as string,
                profiler: key.GetValue(Profiler) as string,
                profilerPath: key.GetValue(ProfilerPath) as string,
                location: $@"{hiveName}\{path}",
                name: hive == RegistryHive.LocalMachine ? "machine environment" : "user environment");
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                     or UnauthorizedAccessException
                                     or IOException)
        {
            Interlocked.Increment(ref _unreadableLocations);
        }
    }

    /// <summary>
    /// Per-service environment blocks. The SCM applies a service's own <c>Environment</c> value to
    /// that service alone, so this is how a profiler is put inside one chosen SYSTEM process without
    /// touching anything another process would read.
    /// </summary>
    private void ReadServiceEnvironments(List<RawAutostart> entries)
    {
        string[] services;
        RegistryKey? root = null;
        try
        {
            var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            root = baseKey.OpenSubKey(Services);
            if (root is null)
            {
                return;
            }
            services = root.GetSubKeyNames();
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                     or UnauthorizedAccessException
                                     or IOException)
        {
            Interlocked.Increment(ref _unreadableLocations);
            root?.Dispose();
            return;
        }

        using (root)
        {
            foreach (var service in services)
            {
                try
                {
                    using var key = root.OpenSubKey(service);
                    // REG_MULTI_SZ of NAME=VALUE, which is how the SCM stores it.
                    if (key?.GetValue("Environment") is not string[] block)
                    {
                        continue;
                    }
                    Add(entries,
                        enabled: Value(block, Enable),
                        profiler: Value(block, Profiler),
                        profilerPath: Value(block, ProfilerPath),
                        location: $@"HKLM\{Services}\{service} [Environment]",
                        name: service);
                }
                catch (Exception ex) when (ex is System.Security.SecurityException
                                             or UnauthorizedAccessException
                                             or IOException)
                {
                    Interlocked.Increment(ref _unreadableLocations);
                }
            }
        }
    }

    /// <summary>
    /// Records the finding when profiling is switched on and something is named to load.
    /// </summary>
    /// <remarks>
    /// Both halves are required. <c>COR_PROFILER</c> alone loads nothing, and reporting it would
    /// flag every machine with a development tool installed; <c>COR_ENABLE_PROFILING=1</c> alone
    /// names no DLL. The pair is the mechanism.
    /// </remarks>
    private static void Add(
        List<RawAutostart> entries,
        string? enabled,
        string? profiler,
        string? profilerPath,
        string location,
        string name)
    {
        if (enabled?.Trim() != "1")
        {
            return;
        }
        var image = !string.IsNullOrWhiteSpace(profilerPath)
            ? Environment.ExpandEnvironmentVariables(profilerPath.Trim())
            : ResolveClsid(profiler);
        if (string.IsNullOrWhiteSpace(image))
        {
            // Enabled with nothing resolvable named. Still reported: the registration is the
            // finding, and one whose image cannot be found is if anything more interesting than one
            // that can. The CLSID is carried as the command so the operator has something to follow.
            image = string.IsNullOrWhiteSpace(profiler) ? null : profiler.Trim();
        }
        if (string.IsNullOrWhiteSpace(image))
        {
            return;
        }
        entries.Add(new RawAutostart(AutostartVector.ProfilerInjection, name, location, image));
    }

    /// <summary>The DLL a profiler CLSID registers, through the same COM lookup as the hijack surface.</summary>
    private static string? ResolveClsid(string? clsid)
    {
        var trimmed = clsid?.Trim();
        if (string.IsNullOrWhiteSpace(trimmed) || trimmed[0] != '{')
        {
            return null;
        }
        // Both views: a 32-bit profiler registers under WOW6432Node and a 64-bit one does not, and
        // a scan that reads one view reports the other as unresolvable.
        return ClsidResolver.ResolveInprocServer(trimmed, RegistryView.Registry64)
            ?? ClsidResolver.ResolveInprocServer(trimmed, RegistryView.Registry32);
    }

    /// <summary>The value of <paramref name="name"/> in a REG_MULTI_SZ <c>NAME=VALUE</c> block.</summary>
    private static string? Value(string[] block, string name)
    {
        foreach (var line in block)
        {
            var separator = line.IndexOf('=', StringComparison.Ordinal);
            if (separator > 0
                && line.AsSpan(0, separator).Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return line[(separator + 1)..].Trim();
            }
        }
        return null;
    }
}
