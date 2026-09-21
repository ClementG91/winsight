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

    public IReadOnlyList<KernelDriver> Scan(CancellationToken cancellationToken = default) =>
        ScanWithCoverage(cancellationToken).Items;

    public AcquisitionSnapshot<KernelDriver> ScanWithCoverage(
        CancellationToken cancellationToken = default)
    {
        var registrationScan = ReadRegistrations(cancellationToken);
        var registrations = registrationScan.Items;
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
                // An image that could not be located was never looked at: not a missing file.
                : registration.ImageSource == DriverImageSource.Unresolvable
                    ? SignatureVerdict.Unknown
                    : SignatureVerdict.Missing;
            results.Add(new KernelDriver(
                registration.Name,
                registration.Kind,
                registration.Start,
                registration.ImagePath,
                registration.ExpectedImagePath,
                verdict,
                KernelDriverTriage.IsWindowsProvided(registration.ImagePath, verdict, systemDirectory),
                registration.ImageSource));
        }
        return new AcquisitionSnapshot<KernelDriver>(
            results, registrationScan.UnreadableSources, registrationScan.UnreadableItems);
    }

    private static AcquisitionSnapshot<Registration> ReadRegistrations(
        CancellationToken cancellationToken)
    {
        var found = new List<Registration>();
        var unreadableItems = 0;
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(ServicesRoot);
            if (services is null)
            {
                return new AcquisitionSnapshot<Registration>(found, unreadableSources: 1);
            }
            foreach (var name in services.GetSubKeyNames())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var (registration, unreadable) = Read(services, name);
                if (unreadable)
                {
                    unreadableItems++;
                }
                if (registration is { } value)
                {
                    found.Add(value);
                }
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                     or UnauthorizedAccessException
                                     or IOException)
        {
            return new AcquisitionSnapshot<Registration>(
                found, unreadableSources: 1, unreadableItems: unreadableItems);
        }
        return new AcquisitionSnapshot<Registration>(
            found, unreadableItems: unreadableItems);
    }

    private static (Registration? Registration, bool Unreadable) Read(
        RegistryKey services, string name)
    {
        try
        {
            using var key = services.OpenSubKey(name);
            if (key?.GetValue("Type") is not int type)
            {
                return (null, false);
            }
            var kind = type switch
            {
                KernelDriverType => DriverKind.Kernel,
                FileSystemDriverType => DriverKind.FileSystem,
                _ => (DriverKind?)null,
            };
            if (kind is null)
            {
                return (null, false);
            }

            var (image, expected, source) = ResolveImage(name, key.GetValue("ImagePath") as string);
            return (new Registration(
                name, kind.Value, StartOf(key.GetValue("Start")), image, expected, source), false);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                     or UnauthorizedAccessException
                                     or IOException)
        {
            return (null, true);
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
    /// <remarks>
    /// Exactly one place is looked at: the registered image, or - only when the registration has
    /// no <c>ImagePath</c>, which twelve registrations on the development machine rely on -
    /// <c>System32\drivers\{service}.sys</c>. Falling back to that default when the registered
    /// image was set but not found let a Microsoft file of the same name stand in for it; see
    /// <see cref="DriverImagePath"/>. A registered value that maps to no local path keeps its raw
    /// text as the expected image, so the report can show what was registered.
    /// </remarks>
    private static (string? ImagePath, string? ExpectedImagePath, DriverImageSource Source) ResolveImage(
        string name, string? registered)
    {
        var location = DriverImagePath.Locate(
            name, registered, Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        if (location.Path is null)
        {
            return (null, location.Registered, DriverImageSource.Unresolvable);
        }

        string full;
        try
        {
            full = Path.GetFullPath(location.Path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return (null, location.Registered ?? location.Path, DriverImageSource.Unresolvable);
        }
        return AutomaticFileAccess.FileExists(full)
            ? (full, full, location.Source)
            : (null, full, location.Source);
    }

    private sealed record Registration(
        string Name,
        DriverKind Kind,
        DriverStart Start,
        string? ImagePath,
        string? ExpectedImagePath,
        DriverImageSource ImageSource);
}
