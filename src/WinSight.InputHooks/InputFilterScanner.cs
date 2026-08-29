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

        var resolved = new List<(InputStack Stack, FilterPosition Position, string Name, string? Path)>();
        var unreadableItems = 0;
        foreach (var (stack, position, name) in found)
        {
            var (path, unreadable) = ResolveDriverPath(name);
            if (unreadable)
            {
                unreadableItems++;
            }
            resolved.Add((stack, position, name, path));
        }

        var paths = resolved
            .Where(entry => entry.Path is not null)
            .Select(entry => entry.Path!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var verdicts = paths.Length == 0
            ? new Dictionary<string, SignatureVerdict>(StringComparer.OrdinalIgnoreCase)
            : _verifier.VerifyMany(paths, cancellationToken);

        var results = new List<InputFilter>(resolved.Count);
        foreach (var (stack, position, name, path) in resolved)
        {
            var verdict = path is not null && verdicts.TryGetValue(path, out var known)
                ? known
                : new SignatureVerdict(SignatureState.Missing, null);
            results.Add(new InputFilter(
                stack,
                position,
                name,
                path,
                verdict,
                InputFilterTriage.IsWindowsClassDriver(stack, name)));
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

    /// <summary>
    /// The driver file a filter name refers to, or null when it is not where drivers live.
    /// </summary>
    /// <remarks>
    /// A filter is named by its service, whose image is conventionally
    /// <c>%SystemRoot%\System32\drivers\{name}.sys</c>. Resolving through the service's own
    /// ImagePath would be more thorough; this covers the overwhelming majority and a filter whose
    /// file cannot be found is itself reported rather than quietly dropped.
    /// </remarks>
    internal static (string? Path, bool Unreadable) ResolveDriverPath(string name)
    {
        try
        {
            if (name.IndexOfAny(['\\', '/']) >= 0 || name is "." or "..")
            {
                return (null, true);
            }

            string? registered = null;
            using (var service = Registry.LocalMachine.OpenSubKey(
                       $@"SYSTEM\CurrentControlSet\Services\{name}"))
            {
                registered = service?.GetValue("ImagePath") as string;
            }

            var candidates = new List<string>();
            if (NormalizeDriverPath(registered) is { } configured)
            {
                candidates.Add(configured);
            }
            candidates.Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", $"{name}.sys"));

            foreach (var candidate in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                string full;
                try
                {
                    full = Path.GetFullPath(candidate);
                }
                catch (Exception ex) when (ex is ArgumentException
                                             or NotSupportedException
                                             or PathTooLongException)
                {
                    continue;
                }
                if (File.Exists(full))
                {
                    return (full, false);
                }
            }
            return (null, false);
        }
        catch (Exception ex) when (ex is ArgumentException
                                     or IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            return (null, true);
        }
    }

    /// <summary>
    /// The absolute image path a service's <c>ImagePath</c> value refers to.
    /// </summary>
    /// <remarks>
    /// Internal rather than private so the four prefix forms can be tested directly. They are the
    /// whole of this method's risk and none of them were reachable from a test: the registry is
    /// read-only here, so exercising them through <see cref="ResolveDriverPath"/> would have meant
    /// writing to HKLM\SYSTEM\CurrentControlSet\Services on the machine running the suite.
    /// </remarks>
    internal static string? NormalizeDriverPath(string? registered)
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
}
