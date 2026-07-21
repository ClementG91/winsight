namespace WinSight.Attribution;

/// <summary>
/// Translates the paths a kernel ETW session reports into the form the rest of WinSight uses.
/// </summary>
/// <remarks>
/// Attribution lives or dies on this. A kernel session does not report the paths an operator sees:
/// a file write arrives as <c>\Device\HarddiskVolume3\Users\me\file.txt</c> and a registry write as
/// <c>\REGISTRY\MACHINE\SOFTWARE\...</c>, while a Guardian finding names
/// <c>C:\Users\me\file.txt</c> and <c>HKLM\SOFTWARE\...</c>. Compared raw, the two never match and
/// every detection would come back unattributed — silently, with all the plumbing apparently
/// working. That failure mode is why this is a separate, injected, unit-tested type rather than a
/// few string replacements inside the ETW callback: the volume map and the current user's SID are
/// machine state, and passing them in is what makes the translation testable without a live trace.
///
/// Null is always the honest answer for something this cannot translate. Attribution names the
/// process that touched an operator's autostart entry or files; a guess there is worse than an
/// unattributed detection.
/// </remarks>
public sealed class KernelPathNormalizer
{
    private const string DevicePrefix = @"\Device\";
    private const string RegistryPrefix = @"\REGISTRY\";
    private const string MachineHive = "MACHINE";
    private const string UserHive = "USER";

    // The Windows Container namespace, which is how user-hive writes actually arrive.
    private const string ContainerHive = "WC";
    private const string UserSiloSuffix = "user_sid";

    private readonly Dictionary<string, string> _deviceToDrive;
    private readonly string? _currentUserSid;

    /// <param name="deviceToDrive">
    /// NT device name to drive letter, e.g. <c>\Device\HarddiskVolume3</c> to <c>C:</c>. Supplied by
    /// the caller because it is machine state; a live provider queries Windows for it.
    /// </param>
    /// <param name="currentUserSid">
    /// The SID whose registry hive should read as <c>HKCU</c>. Null leaves every user hive as
    /// <c>HKU\{sid}</c>, which is correct but less recognisable.
    /// </param>
    public KernelPathNormalizer(
        IReadOnlyDictionary<string, string>? deviceToDrive = null,
        string? currentUserSid = null)
    {
        _deviceToDrive = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in deviceToDrive ?? new Dictionary<string, string>())
        {
            // Stored without the trailing separator so a lookup is a plain segment comparison.
            _deviceToDrive[pair.Key.TrimEnd('\\')] = pair.Value.TrimEnd('\\');
        }
        _currentUserSid = string.IsNullOrWhiteSpace(currentUserSid) ? null : currentUserSid;
    }

    /// <summary>
    /// The Win32 form of a kernel file path, or null when it cannot be translated confidently.
    /// </summary>
    /// <remarks>
    /// A path that is already Win32 is returned as-is: kernel sessions do report some events with
    /// ordinary paths, and refusing those would drop attributions for no reason.
    /// </remarks>
    public string? NormalizeFilePath(string? kernelPath)
    {
        if (string.IsNullOrWhiteSpace(kernelPath))
        {
            return null;
        }
        var path = kernelPath.Trim();

        if (!path.StartsWith(DevicePrefix, StringComparison.OrdinalIgnoreCase))
        {
            // Already drive-qualified (C:\...) or a UNC share: usable as it stands. Anything else
            // is another NT namespace this has no mapping for — \??\ and \\?\GLOBALROOT\ among
            // them — and a guess is not worth making. Path.IsPathFullyQualified is too generous
            // here: it accepts those namespaces, which would then match nothing downstream.
            return IsDriveQualifiedOrUnc(path) ? path : null;
        }

        // Split off the device, which is the first two segments after the prefix in practice
        // (\Device\HarddiskVolume3), but is matched by longest known device so an unusual device
        // name with more segments still resolves.
        var remainder = path[DevicePrefix.Length..];
        var separator = remainder.IndexOf('\\');
        var device = separator < 0 ? remainder : remainder[..separator];
        var rest = separator < 0 ? string.Empty : remainder[(separator + 1)..];

        if (!_deviceToDrive.TryGetValue(DevicePrefix + device, out var drive))
        {
            // An unmapped device is typically a volume without a drive letter. Reporting the raw
            // kernel path would not match anything downstream, so say nothing instead.
            return null;
        }
        return rest.Length == 0 ? drive + '\\' : $"{drive}\\{rest}";
    }

    /// <summary>
    /// The <c>HKLM\...</c> / <c>HKCU\...</c> form of a kernel registry key, or null when it cannot
    /// be translated. Matches the hive abbreviations the persistence enumerators already emit.
    /// </summary>
    public string? NormalizeRegistryKey(string? kernelKey)
    {
        if (string.IsNullOrWhiteSpace(kernelKey))
        {
            return null;
        }
        var key = kernelKey.Trim();

        if (!key.StartsWith(RegistryPrefix, StringComparison.OrdinalIgnoreCase))
        {
            // Already in an abbreviated form (some providers report HKLM\... directly).
            return key.StartsWith("HK", StringComparison.OrdinalIgnoreCase) ? key : null;
        }

        var remainder = key[RegistryPrefix.Length..];
        var separator = remainder.IndexOf('\\');
        var hive = separator < 0 ? remainder : remainder[..separator];
        var rest = separator < 0 ? string.Empty : remainder[(separator + 1)..];

        if (hive.Equals(MachineHive, StringComparison.OrdinalIgnoreCase))
        {
            return Join("HKLM", rest);
        }
        if (hive.Equals(ContainerHive, StringComparison.OrdinalIgnoreCase))
        {
            return NormalizeSiloKey(rest);
        }
        if (!hive.Equals(UserHive, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        // \REGISTRY\USER\{sid}\... — the SID is a segment of its own.
        var sidSeparator = rest.IndexOf('\\');
        var sid = sidSeparator < 0 ? rest : rest[..sidSeparator];
        var underSid = sidSeparator < 0 ? string.Empty : rest[(sidSeparator + 1)..];
        if (sid.Length == 0)
        {
            return null;
        }

        // The _Classes companion hive is a real hive, not a subkey of the user's: keep it distinct
        // rather than folding it into HKCU, where it would collide with a different key.
        if (_currentUserSid is not null && sid.Equals(_currentUserSid, StringComparison.OrdinalIgnoreCase))
        {
            return Join("HKCU", underSid);
        }
        return Join($"HKU\\{sid}", underSid);
    }

    /// <summary>
    /// Translates a key reached through a registry silo, e.g.
    /// <c>\REGISTRY\WC\Silo{guid}user_sid\Software\…</c>.
    /// </summary>
    /// <remarks>
    /// Found by watching a live machine rather than by reading documentation: a plain write to
    /// <c>HKCU\Software\…</c> arrived under <c>\REGISTRY\WC\</c> — the Windows Container namespace —
    /// not under <c>\REGISTRY\USER\</c> at all. Windows routes user-hive access through a silo, so a
    /// normaliser that only knew the two documented hives silently refused every user-hive write
    /// while machine-hive writes sailed through. The scan looked partly healthy, which is the worst
    /// kind of broken.
    ///
    /// Only the shape actually observed is accepted: a silo segment ending in <c>user_sid</c> means
    /// the rest is the current user's hive. Anything else in this namespace is refused rather than
    /// guessed at — a silo can belong to a container whose "user hive" is not this user's at all,
    /// and attributing a container's write to the operator would be a lie.
    /// </remarks>
    private string? NormalizeSiloKey(string rest)
    {
        if (rest.Length == 0)
        {
            return null;
        }
        var separator = rest.IndexOf('\\');
        var silo = separator < 0 ? rest : rest[..separator];
        var underSilo = separator < 0 ? string.Empty : rest[(separator + 1)..];

        return silo.EndsWith(UserSiloSuffix, StringComparison.OrdinalIgnoreCase)
            ? Join("HKCU", underSilo)
            : null;
    }

    private static string Join(string hive, string rest) =>
        rest.Length == 0 ? hive : $"{hive}\\{rest}";

    /// <summary>
    /// Whether a path is in a namespace findings actually use: <c>C:\...</c> or <c>\\server\share</c>.
    /// The device-prefixed and object-manager namespaces are handled (or refused) elsewhere.
    /// </summary>
    private static bool IsDriveQualifiedOrUnc(string path)
    {
        if (path.Length >= 3
            && char.IsLetter(path[0])
            && path[1] == ':'
            && (path[2] == '\\' || path[2] == '/'))
        {
            return true;
        }
        // A plain UNC share, but not the \\?\ or \\.\ device namespaces that merely look like one.
        return path.StartsWith(@"\\", StringComparison.Ordinal)
            && !path.StartsWith(@"\\?\", StringComparison.Ordinal)
            && !path.StartsWith(@"\\.\", StringComparison.Ordinal);
    }
}
