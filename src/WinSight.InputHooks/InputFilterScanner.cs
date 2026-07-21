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

    public IReadOnlyList<InputFilter> Scan(CancellationToken cancellationToken = default)
    {
        var found = new List<(InputStack Stack, FilterPosition Position, string Name)>();
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
                foreach (var name in ReadFilterNames(classGuid, valueName))
                {
                    found.Add((stack, position, name));
                }
            }
        }

        var paths = found
            .Select(entry => ResolveDriverPath(entry.Name))
            .Where(path => path is not null)
            .Select(path => path!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var verdicts = paths.Length == 0
            ? new Dictionary<string, SignatureVerdict>(StringComparer.OrdinalIgnoreCase)
            : _verifier.VerifyMany(paths, cancellationToken);

        var results = new List<InputFilter>(found.Count);
        foreach (var (stack, position, name) in found)
        {
            var path = ResolveDriverPath(name);
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
        return results;
    }

    private static string[] ReadFilterNames(string classGuid, string valueName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"{ClassRoot}\{classGuid}");
            // REG_MULTI_SZ. Absent simply means no filters of that position, which is the common case.
            return key?.GetValue(valueName) is string[] names
                ? names.Where(name => !string.IsNullOrWhiteSpace(name)).Select(name => name.Trim()).ToArray()
                : [];
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                     or UnauthorizedAccessException
                                     or IOException)
        {
            // Reading the class key is not something an unprivileged user is normally denied, but
            // a locked-down machine must degrade to "nothing to report" rather than fail the scan.
            return [];
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
    private static string? ResolveDriverPath(string name)
    {
        try
        {
            var candidate = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", $"{name}.sys");
            return File.Exists(candidate) ? candidate : null;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
