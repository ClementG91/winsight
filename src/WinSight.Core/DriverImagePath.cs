namespace WinSight.Core;

/// <summary>How the image of a driver service was located.</summary>
public enum DriverImageSource
{
    /// <summary>
    /// The service has no <c>ImagePath</c>, so Windows loads <c>System32\drivers\{service}.sys</c>.
    /// </summary>
    Default,

    /// <summary>The service's <c>ImagePath</c>, mapped to a local Win32 path.</summary>
    Registered,

    /// <summary>
    /// The service's <c>ImagePath</c> names something no local Win32 path reaches - a share, or an
    /// object-manager name other than a drive letter - so its image cannot be verified from here.
    /// </summary>
    Unresolvable,
}

/// <summary>Where a driver service's image is, as far as a Win32 path can say.</summary>
/// <param name="Source">How it was located.</param>
/// <param name="Path">
/// The local path to verify, or null when <paramref name="Source"/> is
/// <see cref="DriverImageSource.Unresolvable"/>. Not checked for existence.
/// </param>
/// <param name="Registered">The <c>ImagePath</c> value as registered, or null when there is none.</param>
public readonly record struct DriverImageLocation(DriverImageSource Source, string? Path, string? Registered);

/// <summary>
/// Maps a driver service's registered <c>ImagePath</c> to the file Windows loads.
/// </summary>
/// <remarks>
/// <b>One rule for both scans, and the fallback it replaces.</b> The driver and input-filter scans
/// each carried a copy of this mapping, and both fell back to <c>System32\drivers\{service}.sys</c>
/// whenever the registered image could not be mapped or found - even when <c>ImagePath</c> was set.
/// Windows uses that default only when the value is absent. A registration pointing somewhere the
/// scan could not follow was therefore verified against the in-box file of the same name, inherited
/// its Microsoft signature and was filed as shipped by Windows. The default now applies only when
/// there is no value; a value that does not map is reported as unresolvable, and one that maps to a
/// file that is not there is reported as missing, under its own path.
///
/// <b>What maps.</b> Kernel <c>ImagePath</c> values are NT paths: <c>\SystemRoot\...</c>, a DOS
/// device path <c>\??\C:\...</c> (also spelt <c>\DosDevices\</c> and <c>\GLOBAL??\</c>), or a path
/// relative to the Windows directory. A drive-qualified path is taken as written. Anything else that
/// starts with a separator is an object-manager name - <c>\Device\HarddiskVolume3\...</c>,
/// <c>\??\GLOBALROOT\...</c>, <c>\??\Volume{...}\...</c> - which no Win32 path reaches: combining it
/// with the current drive or the working directory would verify an unrelated file. None of the 456
/// driver registrations on the development machine uses one. A share is refused before anything
/// touches the network, so a read-only scan never authenticates to a registry-chosen server.
/// </remarks>
public static class DriverImagePath
{
    private static readonly string[] SystemRootPrefixes = [@"\SystemRoot\", @"SystemRoot\"];
    private static readonly string[] DosDevicePrefixes = [@"\??\", @"\DosDevices\", @"\GLOBAL??\"];

    /// <summary>Where Windows loads the image of <paramref name="serviceName"/> from.</summary>
    /// <param name="serviceName">The service key name.</param>
    /// <param name="registered">Its <c>ImagePath</c> value, or null when absent.</param>
    /// <param name="windowsDirectory">The Windows directory <c>\SystemRoot</c> stands for.</param>
    public static DriverImageLocation Locate(string serviceName, string? registered, string windowsDirectory)
    {
        ArgumentNullException.ThrowIfNull(serviceName);
        ArgumentException.ThrowIfNullOrWhiteSpace(windowsDirectory);

        if (string.IsNullOrWhiteSpace(registered))
        {
            // A key name may contain '/', which a path treats as a separator: the default must not be
            // steered out of the drivers folder by the name it is built from.
            return IsPlainFileName(serviceName)
                ? new DriverImageLocation(
                    DriverImageSource.Default,
                    Path.Combine(windowsDirectory, "System32", "drivers", $"{serviceName}.sys"),
                    null)
                : new DriverImageLocation(DriverImageSource.Unresolvable, null, null);
        }
        return Normalize(registered, windowsDirectory) is { } path
            ? new DriverImageLocation(DriverImageSource.Registered, path, registered)
            : new DriverImageLocation(DriverImageSource.Unresolvable, null, registered);
    }

    /// <summary>
    /// The local Win32 path a registered <c>ImagePath</c> refers to, or null when it names nothing a
    /// Win32 path reaches.
    /// </summary>
    public static string? Normalize(string? registered, string windowsDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(windowsDirectory);
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

        foreach (var prefix in SystemRootPrefixes)
        {
            if (value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return Path.Combine(windowsDirectory, value[prefix.Length..]);
            }
        }
        foreach (var prefix in DosDevicePrefixes)
        {
            if (value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                var dosPath = value[prefix.Length..];
                return IsDriveQualified(dosPath) ? dosPath : null;
            }
        }
        if (IsDriveQualified(value))
        {
            return value;
        }
        // Rooted without a drive: an object-manager name or a share. Also a drive-relative "C:x",
        // which would resolve against whatever directory the scanner happens to run in.
        return Path.IsPathRooted(value) ? null : Path.Combine(windowsDirectory, value);
    }

    private static bool IsDriveQualified(string path) =>
        path.Length >= 3
        && char.IsAsciiLetter(path[0])
        && path[1] == ':'
        && path[2] is '\\' or '/';

    private static bool IsPlainFileName(string name) =>
        !string.IsNullOrWhiteSpace(name)
        && name is not ("." or "..")
        && name.IndexOfAny(['\\', '/', ':']) < 0;
}
