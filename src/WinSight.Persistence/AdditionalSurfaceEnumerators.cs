using Microsoft.Win32;

using WinSight.Core;

namespace WinSight.Persistence;

/// <summary>
/// <c>RunOnceEx</c>, which runs at logon exactly as <c>RunOnce</c> does and was not read.
/// </summary>
/// <remarks>
/// The structure differs from <c>Run</c>, which is why it needs its own enumerator: entries sit two
/// levels deep, under a numbered group. It is also the more interesting of the pair, because almost
/// nothing legitimate uses it and it loads a DLL through <c>Depend</c> in the same pass - so an
/// entry here is nearly always worth reading.
/// </remarks>
public sealed class RunOnceExEnumerator : IAutostartEnumerator
{
    private const string Path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx";

    public string Surface => "RunOnceEx";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } =
    [
        PersistenceWatchTarget.Registry(
            RegistryHive.LocalMachine, RegistryView.Registry64, Path, watchSubtree: true),
        PersistenceWatchTarget.Registry(
            RegistryHive.CurrentUser, RegistryView.Registry64, Path, watchSubtree: true),
    ];

    public IEnumerable<RawAutostart> Enumerate()
    {
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        {
            foreach (var entry in ReadHive(hive))
            {
                yield return entry;
            }
        }
    }

    private static List<RawAutostart> ReadHive(RegistryHive hive)
    {
        var entries = new List<RawAutostart>();
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var root = baseKey.OpenSubKey(Path);
            if (root is null)
            {
                return entries;
            }
            var hiveName = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
            foreach (var group in root.GetSubKeyNames())
            {
                using var section = root.OpenSubKey(group);
                if (section is null)
                {
                    continue;
                }
                foreach (var name in section.GetValueNames())
                {
                    if (section.GetValue(name) is string command && command.Trim().Length > 0)
                    {
                        entries.Add(new RawAutostart(
                            AutostartVector.RunOnceEx,
                            $"{group}\\{name}",
                            $"{hiveName}\\{Path}\\{group}",
                            command));
                    }
                }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or IOException)
        {
            // An unreadable RunOnceEx contributes nothing; the surface count reports the scan.
        }
        return entries;
    }
}

/// <summary>
/// Security packages loaded into LSASS through <c>SecurityProviders</c>.
/// </summary>
/// <remarks>
/// A DLL named here is loaded into the process that holds every credential on the machine, at boot,
/// as SYSTEM. It is a documented persistence and credential-access technique (MITRE T1547.005), it
/// sits beside the LSA packages this scanner already reads, and it was simply not enumerated. The
/// value is a comma-separated list, and Windows ships it empty or with a single provider.
/// </remarks>
public sealed class SecurityProvidersEnumerator : IAutostartEnumerator
{
    private const string Path = @"SYSTEM\CurrentControlSet\Control\SecurityProviders";
    private static readonly char[] Separators = [',', ' '];

    public string Surface => "Security providers";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } =
    [
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path),
    ];

    public IEnumerable<RawAutostart> Enumerate()
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = baseKey.OpenSubKey(Path);
        if (key?.GetValue("SecurityProviders") is not string raw || raw.Trim().Length == 0)
        {
            yield break;
        }
        foreach (var provider in raw.Split(
                     Separators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            yield return new RawAutostart(
                AutostartVector.SecurityProvider,
                provider,
                $"HKLM\\{Path} [SecurityProviders]",
                provider);
        }
    }
}

/// <summary>
/// The just-in-time debugger Windows launches when a process crashes.
/// </summary>
/// <remarks>
/// <c>AeDebug\Debugger</c> names a command line Windows runs, with the crashing process's identity,
/// whenever an unhandled exception reaches it (MITRE T1546.012). Triggering it is trivial - crash
/// anything - so it is a reliable way to have code run, and it was not enumerated. Both registry
/// views are read because a 32-bit crash consults the WOW6432Node twin, exactly as IFEO does.
/// </remarks>
public sealed class JustInTimeDebuggerEnumerator : IAutostartEnumerator
{
    private const string Path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug";

    public string Surface => "Just-in-time debugger";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } =
    [
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path),
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry32, Path),
    ];

    public IEnumerable<RawAutostart> Enumerate()
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var key = baseKey.OpenSubKey(Path);
            if (key?.GetValue("Debugger") is string debugger && debugger.Trim().Length > 0)
            {
                yield return new RawAutostart(
                    AutostartVector.JustInTimeDebugger,
                    "Debugger",
                    $"HKLM\\{RegistryViews.Describe(Path, view)} [Debugger]",
                    debugger);
            }
        }
    }
}

/// <summary>
/// PowerShell profile scripts, which run in every session of the host that loads them.
/// </summary>
/// <remarks>
/// <b>Reported only when one exists.</b> None of these files is created by Windows, so on an
/// ordinary machine this surface is empty and contributes no noise. When one does exist it runs
/// unattended in every PowerShell session that host starts, which is what makes it MITRE T1546.013
/// and worth a look even when the operator wrote it themselves.
///
/// A <c>.ps1</c> carries no Authenticode signature in the ordinary case, so it will read as
/// unsigned. That is accurate rather than alarmist here: unlike the shim databases this scanner
/// deliberately skips for the same reason, a profile script is not something Windows ships by the
/// hundred - each one is a deliberate act by somebody.
/// </remarks>
public sealed class PowerShellProfileEnumerator : IAutostartEnumerator
{
    public string Surface => "PowerShell profiles";

    public IEnumerable<RawAutostart> Enumerate()
    {
        foreach (var (path, label) in CandidateProfiles())
        {
            bool exists;
            try
            {
                exists = AutomaticFileAccess.IsLocal(path) && File.Exists(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }
            if (exists)
            {
                yield return new RawAutostart(
                    AutostartVector.PowerShellProfile, label, path, path);
            }
        }
    }

    private static IEnumerable<(string Path, string Label)> CandidateProfiles()
    {
        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        foreach (var name in new[] { "profile.ps1", "Microsoft.PowerShell_profile.ps1" })
        {
            yield return (
                System.IO.Path.Combine(system32, "WindowsPowerShell", "v1.0", name),
                $"AllUsers\\{name}");
            yield return (
                System.IO.Path.Combine(documents, "WindowsPowerShell", name),
                $"CurrentUser\\{name}");
            // PowerShell 7 keeps its own profile directory beside the Windows PowerShell one.
            yield return (
                System.IO.Path.Combine(documents, "PowerShell", name),
                $"CurrentUser\\pwsh\\{name}");
        }
    }
}
