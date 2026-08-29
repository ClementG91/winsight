using Microsoft.Win32;
using WinSight.Core;

namespace WinSight.Hijack;

/// <summary>A registered service, as the machine holds it.</summary>
/// <param name="Name">The service name.</param>
/// <param name="CommandLine">Its registered <c>ImagePath</c>.</param>
/// <param name="AutoStarts">True when Windows starts it without being asked (boot/system/auto).</param>
public readonly record struct RegisteredService(string Name, string CommandLine, bool AutoStarts);

/// <summary>Reads the machine's registered services. A seam, so the scan is testable.</summary>
public interface IServiceRegistry
{
    IEnumerable<RegisteredService> Enumerate();

    AcquisitionSnapshot<RegisteredService> ReadWithCoverage() =>
        new(Enumerate().ToList());
}

/// <summary>Reads the machine-wide PATH, already split and expanded. A seam, for the same reason.</summary>
public interface IMachinePath
{
    IReadOnlyList<string> Directories();

    AcquisitionSnapshot<string> ReadWithCoverage() => new(Directories());
}

/// <summary>
/// Reads services from <c>HKLM\SYSTEM\CurrentControlSet\Services</c>. No elevation: the key is
/// readable by any user, which is the whole reason this check can ship in the default mode.
/// </summary>
public sealed class RegistryServiceSource : IServiceRegistry
{
    private const string Root = @"SYSTEM\CurrentControlSet\Services";

    public IEnumerable<RegisteredService> Enumerate() => ReadWithCoverage().Items;

    public AcquisitionSnapshot<RegisteredService> ReadWithCoverage()
    {
        var result = new List<RegisteredService>();
        var unreadableItems = 0;
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var services = baseKey.OpenSubKey(Root);
            if (services is null)
            {
                return new AcquisitionSnapshot<RegisteredService>([], unreadableSources: 1);
            }

            foreach (var name in services.GetSubKeyNames())
            {
                string? image = null;
                var autoStarts = false;
                try
                {
                    using var service = services.OpenSubKey(name);
                    if (service is null)
                    {
                        unreadableItems++;
                        continue;
                    }
                    image = service.GetValue("ImagePath") as string;
                    // Start: 0=boot 1=system 2=auto 3=manual 4=disabled.
                    autoStarts = service.GetValue("Start") is int start && start <= 2;
                }
                catch (Exception ex) when (ex is System.Security.SecurityException
                                             or UnauthorizedAccessException
                                             or IOException)
                {
                    unreadableItems++;
                }
                if (!string.IsNullOrWhiteSpace(image))
                {
                    result.Add(new RegisteredService(name, image, autoStarts));
                }
            }
            return new AcquisitionSnapshot<RegisteredService>(result, unreadableItems: unreadableItems);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                     or UnauthorizedAccessException
                                     or IOException)
        {
            return new AcquisitionSnapshot<RegisteredService>(result, unreadableSources: 1, unreadableItems);
        }
    }
}

/// <summary>
/// Reads the machine-wide PATH from the registry rather than from this process's environment.
/// </summary>
/// <remarks>
/// The process environment is a snapshot taken at launch and may carry per-user entries; the
/// registry value is what every service and every new process will actually get. Read unexpanded so
/// the variables are resolved deliberately rather than by whoever happened to set them.
/// </remarks>
public sealed class RegistryMachinePath : IMachinePath
{
    private const string EnvironmentKey =
        @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

    public IReadOnlyList<string> Directories() => ReadWithCoverage().Items;

    public AcquisitionSnapshot<string> ReadWithCoverage()
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var environment = baseKey.OpenSubKey(EnvironmentKey);
            var raw = environment?.GetValue(
                "Path", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
            if (string.IsNullOrWhiteSpace(raw))
            {
                return new AcquisitionSnapshot<string>([]);
            }
            return new AcquisitionSnapshot<string>(raw
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(entry => Environment.ExpandEnvironmentVariables(entry).Trim('"').Trim())
                .Where(entry => entry.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList());
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                     or UnauthorizedAccessException
                                     or IOException)
        {
            return new AcquisitionSnapshot<string>([], unreadableSources: 1);
        }
    }
}

/// <summary>
/// Finds places where a program other than the intended one could end up running: an unquoted
/// service command line, a service directory anyone can write to, or a machine PATH entry anyone
/// can plant into.
/// </summary>
/// <remarks>
/// A privilege-escalation scan rather than a persistence one, and the reason it belongs in a Windows
/// tool specifically: none of these vectors exist on macOS, so nothing in the Objective-See family
/// has an equivalent. A service usually runs as SYSTEM and starts before anyone logs in, so any of
/// these is a straight path from "ordinary user" to "SYSTEM at boot".
/// </remarks>
public sealed class HijackScanner(
    IServiceRegistry? services = null,
    IMachinePath? machinePath = null,
    IWritabilityProbe? probe = null,
    IKnownDllSource? knownDlls = null,
    Func<string, PeImportSet>? readImports = null,
    Func<string, bool>? fileExists = null,
    ISideBySideStore? sideBySideStore = null)
{
    private readonly IServiceRegistry _services = services ?? new RegistryServiceSource();
    private readonly IMachinePath _machinePath = machinePath ?? new RegistryMachinePath();
    private readonly IWritabilityProbe _probe = probe ?? new WritabilityProbe();
    private readonly IKnownDllSource _knownDlls = knownDlls ?? new RegistryKnownDllSource();
    private readonly Func<string, PeImportSet> _readImports = readImports ?? PeImports.ReadFile;
    private readonly Func<string, bool> _fileExists = fileExists ?? File.Exists;
    private readonly ISideBySideStore? _sideBySideStore = sideBySideStore;
    private readonly HijackTriage _triage = new(probe);

    public IReadOnlyList<HijackFinding> Scan(CancellationToken cancellationToken = default)
        => ScanWithCoverage(cancellationToken).Items;

    public AcquisitionSnapshot<HijackFinding> ScanWithCoverage(
        CancellationToken cancellationToken = default)
    {
        var findings = new List<HijackFinding>();
        var services = _services.ReadWithCoverage();
        var paths = _machinePath.ReadWithCoverage();
        var knownDlls = _knownDlls.ReadWithCoverage();
        var pathDirectories = paths.Items;
        var known = knownDlls.Items.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var unreadableSources = services.UnreadableSources + paths.UnreadableSources + knownDlls.UnreadableSources;
        var unreadableItems = services.UnreadableItems + paths.UnreadableItems + knownDlls.UnreadableItems;
        var unreadableProbeStart = (_probe as IWritabilityProbeCoverage)?.UnreadableAttempts ?? 0;
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        // Writability is a fact about a directory, not about the service that named it, and the
        // search orders of ~90 services overlap almost entirely. Asking once per directory keeps
        // the probe count proportional to the machine rather than to the service list.
        // One store per scan: the answers it gives are facts about the machine, and the index it
        // builds is meant to be built once rather than once per service. Injectable so a test can
        // exercise the rule without walking the real WinSxS tree, which is the difference between a
        // suite that runs in milliseconds and one that runs in minutes.
        var sideBySide = _sideBySideStore ?? new SideBySideStore(windows);
        var plantable = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        bool CanPlantIn(string directory)
        {
            if (!plantable.TryGetValue(directory, out var writable))
            {
                writable = Directory.Exists(directory)
                    && _probe.CanCreate(Path.Combine(directory, "winsight-probe.dll"));
                plantable[directory] = writable;
            }
            return writable;
        }

        foreach (var service in services.Items)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_triage.AssessCommandLine(service.Name, service.CommandLine) is { } unquoted)
            {
                findings.Add(unquoted);
            }
            // Only services Windows starts by itself: a manual service that never runs is not a
            // boot-time escalation path, and checking all of them would triple the probe count for
            // no added signal.
            if (!service.AutoStarts)
            {
                continue;
            }
            if (ExecutableDirectory(service.CommandLine) is not { } directory)
            {
                continue;
            }
            if (_triage.AssessServiceDirectory(service.Name, directory) is { } writable)
            {
                findings.Add(writable);
            }
            var importAssessment = AssessImports(
                service, directory, system, windows, pathDirectories, known, CanPlantIn, sideBySide);
            findings.AddRange(importAssessment.Findings);
            unreadableItems += importAssessment.UnreadableItems;
        }

        foreach (var directory in pathDirectories)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_triage.AssessPathEntry(directory) is { } entry)
            {
                findings.Add(entry);
            }
        }

        // Worst first: an occupied candidate is already a file on disk, an exploitable one is one
        // write away, and a latent one is a hygiene note.
        var ordered = findings
            .OrderBy(f => f.Exposure switch
            {
                HijackExposure.Occupied => 0,
                HijackExposure.Exploitable => 1,
                _ => 2,
            })
            .ThenBy(f => f.Subject, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var unreadableProbeEnd = (_probe as IWritabilityProbeCoverage)?.UnreadableAttempts ?? unreadableProbeStart;
        unreadableItems += Math.Max(0, unreadableProbeEnd - unreadableProbeStart);
        return new AcquisitionSnapshot<HijackFinding>(ordered, unreadableSources, unreadableItems);
    }

    /// <summary>
    /// The directory holding a service's executable, or null when the command line does not name
    /// one this can be sure of.
    /// </summary>
    /// <remarks>
    /// Deliberately conservative. A driver's NT path is loaded by the kernel, not from a directory
    /// search; a command line with no <c>.exe</c> cannot be split reliably. Guessing here would
    /// probe — and then accuse — the wrong directory.
    ///
    /// The unquoted case defers to <see cref="UnquotedPath.ExecutableSpan"/> rather than repeating
    /// the parse. It used to take the first <c>.exe</c> in the string with no end-of-token check, so
    /// a command line whose path contains an earlier <c>.exe</c> — say
    /// <c>C:\Tools\7z.exe.bak\svc.exe -k</c> — resolved to <c>C:\Tools</c> and the scan would probe,
    /// and on a writable machine accuse, a directory the service does not live in. Two readings of
    /// one string in one feature have to agree, or the harder-won one is wasted.
    /// </remarks>
    /// <summary>
    /// The phantom imports of one auto-starting service's executable.
    /// </summary>
    /// <remarks>
    /// Restricted to auto-start services for the same reason the directory check is: a phantom
    /// import in a program that never runs is not a boot-time escalation path, and reading every
    /// registered service's image would multiply the I/O for no added signal.
    /// </remarks>
    private (IReadOnlyList<HijackFinding> Findings, int UnreadableItems) AssessImports(
        RegisteredService service,
        string directory,
        string system,
        string windows,
        IReadOnlyList<string> pathDirectories,
        IReadOnlySet<string> known,
        Func<string, bool> canPlantIn,
        ISideBySideStore sideBySide)
    {
        if (ExecutablePath(service.CommandLine) is not { } image || !_fileExists(image))
        {
            return ([], 0);
        }
        var imports = _readImports(image);
        if (!imports.IsReadable)
        {
            return ([], 1);
        }
        if (imports.IsEmpty)
        {
            return ([], 0);
        }

        // The bitness the PE parse already established decides which directory "the system
        // directory" means. A 32-bit process is served SysWOW64 by the file-system redirector, so
        // searching System32 for it reported the ordinary case as a phantom import.
        var systemForImage = DllSearchOrder.SystemDirectoryFor(
            imports.Is64Bit ?? true, system, windows);
        var order = DllSearchOrder.For(directory, systemForImage, windows, pathDirectories);
        var unresolvable = 0;
        return (PhantomDllRule.Find(
                imports, order, known, _fileExists, canPlantIn,
                dll =>
                {
                    // Null means the store could not be searched. That is a gap in the observation,
                    // and this codebase never turns one into an accusation: the import is skipped
                    // and counted, not reported.
                    var inStore = sideBySide.Contains(dll);
                    if (inStore is null)
                    {
                        unresolvable++;
                        return true;
                    }
                    return inStore.Value;
                })
            .Select(phantom => new HijackFinding(
                HijackKind.PhantomImport,
                $"{service.Name}:{phantom.Dll}",
                image,
                // Nothing occupies a phantom slot by definition, so the grade is only ever whether
                // someone can fill it today.
                phantom.PlantableAt is null ? HijackExposure.Latent : HijackExposure.Exploitable,
                [phantom.Dll],
                phantom.PlantableAt))
            .ToList(), unresolvable);
    }

    /// <summary>
    /// The executable a command line names, or null when it does not name one this can be sure of.
    /// </summary>
    internal static string? ExecutablePath(string? commandLine)
    {
        var line = commandLine?.Trim();
        if (string.IsNullOrEmpty(line) || line.StartsWith('\\'))
        {
            return null;
        }
        string? executable;
        if (line.StartsWith('"'))
        {
            var close = line.IndexOf('"', 1);
            executable = close <= 1 ? null : line[1..close];
        }
        else
        {
            executable = UnquotedPath.ExecutableSpan(line);
        }
        try
        {
            return executable is not null && Path.IsPathFullyQualified(executable)
                ? Environment.ExpandEnvironmentVariables(executable)
                : null;
        }
        catch (Exception ex) when (ex is ArgumentException or PathTooLongException)
        {
            return null;
        }
    }

    internal static string? ExecutableDirectory(string? commandLine)
    {
        var line = commandLine?.Trim();
        if (string.IsNullOrEmpty(line) || line.StartsWith('\\'))
        {
            return null;
        }

        string? executable;
        if (line.StartsWith('"'))
        {
            var close = line.IndexOf('"', 1);
            if (close <= 1)
            {
                return null;
            }
            executable = line[1..close];
        }
        else
        {
            executable = UnquotedPath.ExecutableSpan(line);
            if (executable is null)
            {
                return null;
            }
        }

        try
        {
            var directory = Path.GetDirectoryName(executable);
            return string.IsNullOrEmpty(directory) || !Path.IsPathFullyQualified(directory)
                ? null
                : directory;
        }
        catch (Exception ex) when (ex is ArgumentException or PathTooLongException)
        {
            return null;
        }
    }
}
