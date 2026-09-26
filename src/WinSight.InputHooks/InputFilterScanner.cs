using Microsoft.Win32;

using WinSight.Core;

namespace WinSight.InputHooks;

/// <summary>
/// Lists the kernel drivers sitting in this machine's keyboard and mouse paths.
/// </summary>
/// <remarks>
/// Windows records them as <c>UpperFilters</c>/<c>LowerFilters</c> on the device setup class keys,
/// so this is a plain registry read plus the same Authenticode verification every other scan uses —
/// no elevation, no driver of our own. The judgement about what the result means lives in
/// <see cref="InputFilterTriage"/>, which is pure and tested; this type only gathers.
/// </remarks>
public sealed class InputFilterScanner(ISignatureVerifier? verifier = null)
{
    // Device setup classes. These GUIDs are fixed by Windows.
    private const string KeyboardClass = "{4D36E96B-E325-11CE-BFC1-08002BE10318}";
    private const string MouseClass = "{4D36E96F-E325-11CE-BFC1-08002BE10318}";
    private const string ClassRoot = @"SYSTEM\CurrentControlSet\Control\Class";

    private readonly ISignatureVerifier _verifier = verifier ?? new CachingSignatureVerifier(new NativeSignatureVerifier());

    public IReadOnlyList<InputFilter> Scan(CancellationToken cancellationToken = default) =>
        ScanWithCoverage(cancellationToken).Items;

    public AcquisitionSnapshot<InputFilter> ScanWithCoverage(
        CancellationToken cancellationToken = default)
    {
        var found = new List<(InputStack Stack, FilterPosition Position, string Name)>();
        var unreadableSurfaces = 0;
        foreach (var (stack, classGuid) in new[]
                 {
                     (InputStack.Keyboard, KeyboardClass),
                     (InputStack.Mouse, MouseClass),
                 })
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var (position, valueName) in new[]
                     {
                         (FilterPosition.Upper, "UpperFilters"),
                         (FilterPosition.Lower, "LowerFilters"),
                     })
            {
                var (names, unreadable) = ReadFilterNames(classGuid, valueName);
                if (unreadable)
                {
                    unreadableSurfaces++;
                }
                foreach (var name in names)
                {
                    found.Add((stack, position, name));
                }
            }
        }

        var resolved = new List<(InputStack Stack, FilterPosition Position, string Name, ResolvedDriver Driver)>();
        var unreadableItems = 0;
        foreach (var (stack, position, name) in found)
        {
            var driver = ResolveDriverPath(name);
            if (driver.Unreadable)
            {
                unreadableItems++;
            }
            resolved.Add((stack, position, name, driver));
        }

        var paths = resolved
            .Where(entry => entry.Driver.Path is not null)
            .Select(entry => entry.Driver.Path!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var verdicts = paths.Length == 0
            ? new Dictionary<string, SignatureVerdict>(StringComparer.OrdinalIgnoreCase)
            : _verifier.VerifyMany(paths, cancellationToken);

        var systemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var results = new List<InputFilter>(resolved.Count);
        foreach (var (stack, position, name, driver) in resolved)
        {
            var verdict = driver.Path is not null && verdicts.TryGetValue(driver.Path, out var known)
                ? known
                // A registration that could not be read, or an image that could not be located, was
                // never looked at: that is not a missing file.
                : driver.Unreadable || driver.Source == DriverImageSource.Unresolvable
                    ? SignatureVerdict.Unknown
                    : SignatureVerdict.Missing;
            results.Add(new InputFilter(
                stack,
                position,
                name,
                driver.Path,
                verdict,
                InputFilterTriage.IsWindowsClassDriver(stack, name, driver.Path, verdict, systemDirectory),
                driver.Source,
                driver.Registered));
        }
        return new AcquisitionSnapshot<InputFilter>(
            results, unreadableSurfaces, unreadableItems);
    }

    private static (string[] Names, bool Unreadable) ReadFilterNames(
        string classGuid, string valueName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"{ClassRoot}\{classGuid}");
            // REG_MULTI_SZ. Absent simply means no filters of that position, which is the common case.
            return (key?.GetValue(valueName) is string[] names
                ? names.Where(name => !string.IsNullOrWhiteSpace(name)).Select(name => name.Trim()).ToArray()
                : [], false);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                     or UnauthorizedAccessException
                                     or IOException)
        {
            return ([], true);
        }
    }

    /// <summary>What a filter name resolved to.</summary>
    /// <param name="Path">The driver file on disk, or null when it is not there or was not located.</param>
    /// <param name="Source">Where the image location came from.</param>
    /// <param name="Registered">The service's <c>ImagePath</c> as registered, or null when absent.</param>
    /// <param name="Unreadable">True when the registration itself could not be read.</param>
    internal readonly record struct ResolvedDriver(
        string? Path, DriverImageSource Source, string? Registered, bool Unreadable);

    /// <summary>
    /// The driver file a filter name refers to: the image its service registers, or - only when the
    /// service registers none - <c>%SystemRoot%\System32\drivers\{name}.sys</c>, where Windows then
    /// loads it from.
    /// </summary>
    /// <remarks>
    /// A filter whose file cannot be found is itself reported rather than quietly dropped. It is
    /// never replaced by the same-named file in the drivers folder: a filter registered elsewhere,
    /// or somewhere no local path reaches, would otherwise be verified as the in-box driver.
    /// </remarks>
    internal static ResolvedDriver ResolveDriverPath(string name)
    {
        try
        {
            if (name.IndexOfAny(['\\', '/']) >= 0 || name is "." or "..")
            {
                return new ResolvedDriver(null, DriverImageSource.Unresolvable, null, true);
            }

            string? registered;
            using (var service = Registry.LocalMachine.OpenSubKey(
                       $@"SYSTEM\CurrentControlSet\Services\{name}"))
            {
                registered = service?.GetValue("ImagePath") as string;
            }

            var location = DriverImagePath.Locate(
                name, registered, Environment.GetFolderPath(Environment.SpecialFolder.Windows));
            if (location.Path is null)
            {
                return new ResolvedDriver(null, DriverImageSource.Unresolvable, registered, false);
            }

            string full;
            try
            {
                full = Path.GetFullPath(location.Path);
            }
            catch (Exception ex) when (ex is ArgumentException
                                         or NotSupportedException
                                         or PathTooLongException)
            {
                return new ResolvedDriver(null, DriverImageSource.Unresolvable, registered, false);
            }
            return new ResolvedDriver(
                AutomaticFileAccess.FileExists(full) ? full : null, location.Source, registered, false);
        }
        catch (Exception ex) when (ex is ArgumentException
                                     or IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            return new ResolvedDriver(null, DriverImageSource.Registered, null, true);
        }
    }

    /// <summary>
    /// The absolute image path a service's <c>ImagePath</c> value refers to, or null when it names
    /// nothing a local Win32 path reaches.
    /// </summary>
    /// <remarks>
    /// Internal rather than private so the prefix forms can be tested directly from this assembly's
    /// suite: the registry is read-only here, so exercising them through
    /// <see cref="ResolveDriverPath"/> would have meant writing to
    /// HKLM\SYSTEM\CurrentControlSet\Services on the machine running the suite. The mapping itself
    /// is <see cref="DriverImagePath.Normalize"/>, shared with the kernel-driver scan.
    /// </remarks>
    internal static string? NormalizeDriverPath(string? registered) =>
        DriverImagePath.Normalize(registered, Environment.GetFolderPath(Environment.SpecialFolder.Windows));
}
