using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// .NET profiler injection: a DLL the CLR loads into a managed process because the environment or
/// the registry told it to.
/// </summary>
/// <remarks>
/// <b>What this catches.</b> The CLR loads an arbitrary DLL at startup when
/// <c>COR_ENABLE_PROFILING=1</c> and a profiler GUID is named in <c>COR_PROFILER</c>; an optional
/// <c>COR_PROFILER_PATH</c> locates its DLL. The equivalent <c>CORECLR_*</c> and current
/// <c>DOTNET_*</c> spellings, including architecture-specific paths, are covered too. Nothing about
/// the DLL needs to be a real profiler.
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

    /// <summary>
    /// The managed-assembly variant of the same technique.
    /// </summary>
    /// <remarks>
    /// Instead of a native profiler DLL, the CLR is told to instantiate a managed type as the
    /// process's <c>AppDomainManager</c> before any application code runs. It needs no profiling
    /// flag, it is set the same way in the same places, and it puts an attacker's assembly inside
    /// the target process just as effectively - the managed half of T1574.012, and it was missing
    /// while the native half was covered.
    /// </remarks>
    private const string DomainManagerAssembly = "APPDOMAIN_MANAGER_ASM";
    private const string DomainManagerType = "APPDOMAIN_MANAGER_TYPE";

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
            var scope = hive == RegistryHive.LocalMachine
                ? "machine environment"
                : "user environment";
            AddProfilers(
                entries,
                variable => key.GetValue(variable) as string,
                $@"{hiveName}\{path}",
                scope);
            AddDomainManager(entries,
                assembly: key.GetValue(DomainManagerAssembly) as string,
                type: key.GetValue(DomainManagerType) as string,
                location: $@"{hiveName}\{path}",
                name: scope);
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
                    ReadEnvironmentBlock(
                        entries, block, $@"HKLM\{Services}\{service} [Environment]", service);
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
    /// Both vectors, read out of one <c>NAME=VALUE</c> environment block.
    /// </summary>
    /// <remarks>
    /// Separated from the registry walk so it can be exercised directly. The block a service
    /// carries lives under <c>HKLM\SYSTEM\CurrentControlSet\Services</c>, which a test cannot write
    /// to without installing a service on the machine running it - so the parsing that decides
    /// whether a service is carrying a profiler could otherwise only be verified by hand, on the
    /// stealthiest form of the vector: one chosen SYSTEM process, with nothing another process
    /// would read touched at all.
    /// </remarks>
    internal static void ReadEnvironmentBlock(
        List<RawAutostart> entries, string[] block, string location, string name)
    {
        AddProfilers(entries, variable => Value(block, variable), location, name);
        AddDomainManager(entries,
            assembly: Value(block, DomainManagerAssembly),
            type: Value(block, DomainManagerType),
            location: location,
            name: name);
    }

    /// <summary>
    /// Records the finding when profiling is switched on and something is named to load.
    /// </summary>
    /// <remarks>
    /// Both activation and the profiler GUID are required. A path only locates the required GUID's
    /// DLL and is not itself an activation mechanism.
    /// </remarks>
    private static void AddProfilers(
        List<RawAutostart> entries,
        Func<string, string?> value,
        string location,
        string name)
    {
        AddProfilerFamily(entries, value, "COR", ".NET Framework", location, name);
        AddProfilerFamily(entries, value, "CORECLR", "CoreCLR", location, name);
        // .NET 11 makes DOTNET_* the standard spelling while retaining CORECLR_* for backwards
        // compatibility. Reading it now prevents this detector becoming stale on a runtime update.
        AddProfilerFamily(entries, value, "DOTNET", ".NET", location, name);
    }

    private static void AddProfilerFamily(
        List<RawAutostart> entries,
        Func<string, string?> value,
        string prefix,
        string runtime,
        string location,
        string name)
    {
        var enabled = value($"{prefix}_ENABLE_PROFILING");
        var profiler = value($"{prefix}_PROFILER");
        if (enabled?.Trim() != "1")
        {
            return;
        }
        if (string.IsNullOrWhiteSpace(profiler))
        {
            // Microsoft requires activation and a profiler GUID. A path alone loads nothing.
            return;
        }

        var paths = new (string Variable, string Architecture)[]
        {
            ($"{prefix}_PROFILER_PATH", "all architectures"),
            ($"{prefix}_PROFILER_PATH_32", "x86"),
            ($"{prefix}_PROFILER_PATH_64", "x64"),
            ($"{prefix}_PROFILER_PATH_ARM32", "ARM32"),
            ($"{prefix}_PROFILER_PATH_ARM64", "ARM64"),
        };
        var foundPath = false;
        foreach (var (variable, architecture) in paths)
        {
            var profilerPath = value(variable);
            if (string.IsNullOrWhiteSpace(profilerPath))
            {
                continue;
            }
            foundPath = true;
            entries.Add(new RawAutostart(
                AutostartVector.ProfilerInjection,
                $"{name} ({runtime}, {architecture})",
                location,
                Environment.ExpandEnvironmentVariables(profilerPath.Trim())));
        }
        if (foundPath)
        {
            return;
        }

        // Without a path, Windows resolves the required GUID through COM registration. An
        // unresolvable GUID is still the finding and gives the operator something to follow.
        var image = ResolveClsid(profiler) ?? profiler.Trim();
        entries.Add(new RawAutostart(
            AutostartVector.ProfilerInjection, $"{name} ({runtime})", location, image));
    }

    /// <summary>
    /// Records a managed assembly named as the process's <c>AppDomainManager</c>.
    /// </summary>
    /// <remarks>
    /// The assembly name is enough on its own: unlike a profiler there is no enabling flag, and the
    /// CLR loads whatever is named before any application code runs. The type is carried alongside
    /// it because "which type in that assembly" is the first thing an operator will want.
    /// </remarks>
    private static void AddDomainManager(
        List<RawAutostart> entries, string? assembly, string? type, string location, string name)
    {
        if (string.IsNullOrWhiteSpace(assembly))
        {
            return;
        }
        var command = string.IsNullOrWhiteSpace(type)
            ? assembly.Trim()
            : $"{assembly.Trim()} [{type.Trim()}]";
        entries.Add(new RawAutostart(
            AutostartVector.ProfilerInjection, $"{name} (AppDomainManager)", location, command));
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
