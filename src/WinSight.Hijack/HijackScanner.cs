using Microsoft.Win32;

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
}

/// <summary>Reads the machine-wide PATH, already split and expanded. A seam, for the same reason.</summary>
public interface IMachinePath
{
    IReadOnlyList<string> Directories();
}

/// <summary>
/// Reads services from <c>HKLM\SYSTEM\CurrentControlSet\Services</c>. No elevation: the key is
/// readable by any user, which is the whole reason this check can ship in the default mode.
/// </summary>
public sealed class RegistryServiceSource : IServiceRegistry
{
    private const string Root = @"SYSTEM\CurrentControlSet\Services";

    public IEnumerable<RegisteredService> Enumerate()
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var services = baseKey.OpenSubKey(Root);
        if (services is null)
        {
            yield break;
        }

        foreach (var name in services.GetSubKeyNames())
        {
            string? image = null;
            var autoStarts = false;
            try
            {
                using var service = services.OpenSubKey(name);
                image = service?.GetValue("ImagePath") as string;
                // Start: 0=boot 1=system 2=auto 3=manual 4=disabled.
                autoStarts = service?.GetValue("Start") is int start && start <= 2;
            }
            catch (Exception ex) when (ex is System.Security.SecurityException
                                         or UnauthorizedAccessException
                                         or IOException)
            {
                // One unreadable service must not cost the rest of the sweep.
            }
            if (!string.IsNullOrWhiteSpace(image))
            {
                yield return new RegisteredService(name, image, autoStarts);
            }
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

    public IReadOnlyList<string> Directories()
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var environment = baseKey.OpenSubKey(EnvironmentKey);
            var raw = environment?.GetValue(
                "Path", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
            if (string.IsNullOrWhiteSpace(raw))
            {
                return [];
            }
            return raw
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(entry => Environment.ExpandEnvironmentVariables(entry).Trim('"').Trim())
                .Where(entry => entry.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                     or UnauthorizedAccessException
                                     or IOException)
        {
            return [];
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
    IWritabilityProbe? probe = null)
{
    private readonly IServiceRegistry _services = services ?? new RegistryServiceSource();
    private readonly IMachinePath _machinePath = machinePath ?? new RegistryMachinePath();
    private readonly HijackTriage _triage = new(probe);

    public IReadOnlyList<HijackFinding> Scan(CancellationToken cancellationToken = default)
    {
        var findings = new List<HijackFinding>();

        foreach (var service in _services.Enumerate())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_triage.AssessCommandLine(service.Name, service.CommandLine) is { } unquoted)
            {
                findings.Add(unquoted);
            }
            // Only services Windows starts by itself: a manual service that never runs is not a
            // boot-time escalation path, and checking all of them would triple the probe count for
            // no added signal.
            if (service.AutoStarts
                && ExecutableDirectory(service.CommandLine) is { } directory
                && _triage.AssessServiceDirectory(service.Name, directory) is { } writable)
            {
                findings.Add(writable);
            }
        }

        foreach (var directory in _machinePath.Directories())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_triage.AssessPathEntry(directory) is { } entry)
            {
                findings.Add(entry);
            }
        }

        // Worst first: an occupied candidate is already a file on disk, an exploitable one is one
        // write away, and a latent one is a hygiene note.
        return findings
            .OrderBy(f => f.Exposure switch
            {
                HijackExposure.Occupied => 0,
                HijackExposure.Exploitable => 1,
                _ => 2,
            })
            .ThenBy(f => f.Subject, StringComparer.OrdinalIgnoreCase)
            .ToList();
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
