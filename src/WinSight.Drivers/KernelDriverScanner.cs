using Microsoft.Win32;

using WinSight.Core;

namespace WinSight.Drivers;

/// <summary>
/// Lists the kernel-mode drivers registered on this machine.
/// </summary>
/// <remarks>
/// The service control manager's own registry is the source: every driver Windows can
/// load has a key under <c>HKLM\SYSTEM\CurrentControlSet\Services</c> carrying its type,
/// its start disposition and the image to load. That is a plain read plus the same
/// Authenticode verification every other scan uses — no elevation, no driver of our own.
/// The judgement about what the result means lives in <see cref="KernelDriverTriage"/>,
/// which is pure and tested; this type only gathers.
///
/// <b>Why not <c>EnumDeviceDrivers</c>, which would name the drivers actually resident.</b>
/// Since Windows 8.1 it returns zeroed load addresses to a process that is not elevated,
/// as an ASLR-disclosure defence. The call still succeeds and still reports the right
/// count, but every address is 0, so <c>GetDeviceDriverFileName</c> resolves all of them
/// to whatever sits at 0 — on this machine, 232 entries all naming <c>ntoskrnl.exe</c>.
/// A residency list that silently answers with the same file 232 times is worse than no
/// residency list, so the scan reports what is *registered* and says when Windows loads
/// it, and does not claim to know what is resident. Earning that claim would cost the
/// elevation this whole program is built to avoid.
/// </remarks>
public sealed class KernelDriverScanner(ISignatureVerifier? verifier = null)
{
    private const string ServicesRoot = @"SYSTEM\CurrentControlSet\Services";

    // SERVICE_KERNEL_DRIVER and SERVICE_FILE_SYSTEM_DRIVER. Every other Type value is a
    // user-mode service, which the processes scan already covers.
    private const int KernelDriverType = 1;
    private const int FileSystemDriverType = 2;

    private readonly ISignatureVerifier _verifier =
        verifier ?? new CachingSignatureVerifier(new NativeSignatureVerifier());

    public IReadOnlyList<KernelDriver> Scan(CancellationToken cancellationToken = default)
    {
        var registrations = ReadRegistrations(cancellationToken);
        var paths = registrations
            .Where(registration => registration.ImagePath is not null)
            .Select(registration => registration.ImagePath!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var verdicts = paths.Length == 0
            ? new Dictionary<string, SignatureVerdict>(StringComparer.OrdinalIgnoreCase)
            : _verifier.VerifyMany(paths, cancellationToken);

        var systemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var results = new List<KernelDriver>(registrations.Count);
        foreach (var registration in registrations)
        {
            var verdict = registration.ImagePath is not null && verdicts.TryGetValue(registration.ImagePath, out var known)
                ? known
                : SignatureVerdict.Missing;
            results.Add(new KernelDriver(
                registration.Name,
                registration.Kind,
                registration.Start,
                registration.ImagePath,
                registration.ExpectedImagePath,
                verdict,
                KernelDriverTriage.IsWindowsProvided(registration.ImagePath, verdict, systemDirectory)));
        }
        return results;
    }

    private static List<Registration> ReadRegistrations(CancellationToken cancellationToken)
    {
        var found = new List<Registration>();
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(ServicesRoot);
            if (services is null)
            {
                return found;
            }
            foreach (var name in services.GetSubKeyNames())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (Read(services, name) is { } registration)
                {
                    found.Add(registration);
                }
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                     or UnauthorizedAccessException
                                     or IOException)
        {
            // The services key is readable by any user on a normal machine, but a
            // locked-down one must degrade to "nothing to report" rather than fail the scan.
        }
        return found;
    }

    private static Registration? Read(RegistryKey services, string name)
    {
        try
        {
            using var key = services.OpenSubKey(name);
            if (key?.GetValue("Type") is not int type)
            {
                return null;
            }
            var kind = type switch
            {
                KernelDriverType => DriverKind.Kernel,
                FileSystemDriverType => DriverKind.FileSystem,
                _ => (DriverKind?)null,
            };
            if (kind is null)
            {
                return null;
            }

            var (image, expected) = ResolveImage(name, key.GetValue("ImagePath") as string);
            return new Registration(name, kind.Value, StartOf(key.GetValue("Start")), image, expected);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                     or UnauthorizedAccessException
                                     or IOException)
        {
            // One unreadable service key must not cost the operator the other few hundred.
            return null;
        }
    }

    private static DriverStart StartOf(object? value) => value is int start
        ? start switch
        {
            0 => DriverStart.Boot,
            1 => DriverStart.System,
            2 => DriverStart.Automatic,
            3 => DriverStart.Manual,
            4 => DriverStart.Disabled,
            _ => DriverStart.Unknown,
        }
        : DriverStart.Unknown;

    /// <summary>
    /// The driver file a registration points at, plus where it was expected. The second
    /// half is why this does not just return a path: a registration naming an image that
    /// is gone is itself a finding, and reporting it needs the name of the absent file.
    /// </summary>
    private static (string? ImagePath, string? ExpectedImagePath) ResolveImage(string name, string? registered)
    {
        string? expected = null;
        foreach (var candidate in Candidates(name, registered))
        {
            string full;
            try
            {
                full = Path.GetFullPath(candidate);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                continue;
            }
            expected ??= full;
            if (File.Exists(full))
            {
                return (full, full);
            }
        }
        return (null, expected);
    }

    /// <summary>
    /// The places a driver image may be, best guess first, so the first candidate is
    /// also the honest "expected" path when none of them exist.
    /// </summary>
    private static IEnumerable<string> Candidates(string name, string? registered)
    {
        if (Normalize(registered) is { } fromRegistry)
        {
            yield return fromRegistry;
        }

        // A driver registration may omit ImagePath entirely, in which case the service
        // control manager loads System32\drivers\{service}.sys. Twelve registrations on
        // this machine rely on that default, and dropping them would hide exactly the
        // sort of minimal entry a rootkit would write.
        yield return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", $"{name}.sys");
    }

    /// <summary>
    /// Maps a registered image path into a form the Win32 file APIs can open.
    /// </summary>
    /// <remarks>
    /// Driver ImagePath values are NT paths, not command lines: <c>\SystemRoot\...</c>,
    /// <c>\??\C:\...</c>, or a bare <c>System32\drivers\x.sys</c> taken as relative to
    /// the Windows directory. Unlike a service's executable there are never arguments to
    /// strip. Without this mapping every Windows driver resolves to "no image" and the
    /// scan reports several hundred phantom orphans.
    /// </remarks>
    private static string? Normalize(string? registered)
    {
        if (string.IsNullOrWhiteSpace(registered))
        {
            return null;
        }

        string value;
        try
        {
            value = Environment.ExpandEnvironmentVariables(registered.Trim()).Trim('"').Trim();
        }
        catch (ArgumentException)
        {
            return null;
        }
        if (value.Length == 0)
        {
            return null;
        }

        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        const string systemRootPrefix = @"\SystemRoot\";
        const string bareSystemRootPrefix = @"SystemRoot\";
        const string devicePrefix = @"\??\";

        if (value.StartsWith(systemRootPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return Path.Combine(windows, value[systemRootPrefix.Length..]);
        }
        if (value.StartsWith(bareSystemRootPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return Path.Combine(windows, value[bareSystemRootPrefix.Length..]);
        }
        if (value.StartsWith(devicePrefix, StringComparison.Ordinal))
        {
            return value[devicePrefix.Length..];
        }
        return Path.IsPathRooted(value) ? value : Path.Combine(windows, value);
    }

    private sealed record Registration(
        string Name,
        DriverKind Kind,
        DriverStart Start,
        string? ImagePath,
        string? ExpectedImagePath);
}
