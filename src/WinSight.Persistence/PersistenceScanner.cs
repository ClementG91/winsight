using WinSight.Core;

namespace WinSight.Persistence;

/// <summary>
/// KnockKnock-class scanner: sweeps every registered autostart surface, resolves each
/// item's on-disk executable, and attaches its Authenticode verdict. Read-only, it
/// reveals what persists; it never removes anything.
/// </summary>
public sealed class PersistenceScanner
{
    private readonly IReadOnlyList<IAutostartEnumerator> _enumerators;
    private readonly ISignatureVerifier _verifier;

    public PersistenceScanner(
        IReadOnlyList<IAutostartEnumerator>? enumerators = null,
        ISignatureVerifier? verifier = null)
    {
        _enumerators = enumerators ?? DefaultEnumerators();
        _verifier = verifier ?? new NativeSignatureVerifier();
    }

    /// <summary>The autostart surfaces covered by a default scan (Phase 1).</summary>
    public static IReadOnlyList<IAutostartEnumerator> DefaultEnumerators() =>
        new IAutostartEnumerator[]
        {
            new RunKeyEnumerator(),
            new UserHiveEnumerator(),
            new ServiceEnumerator(),
            new WinlogonEnumerator(),
            new ScheduledTaskEnumerator(),
            new AppInitDllsEnumerator(),
            new ImageHijackEnumerator(),
            new ActiveSetupEnumerator(),
            new BootExecuteEnumerator(),
            new WmiSubscriptionEnumerator(),
            new StartupFolderEnumerator(),
            new LsaPackagesEnumerator(),
            new PrintMonitorEnumerator(),
            new NetshHelperEnumerator(),
            new ComHijackEnumerator(),
            new AppCertDllsEnumerator(),
            new TimeProviderEnumerator(),
            new ScreensaverEnumerator(),
            new SilentProcessExitEnumerator(),
            new CredentialProviderEnumerator(),
            new BrowserHelperObjectEnumerator(),
            new WindowsLoadRunEnumerator(),
            new PrintProviderEnumerator(),
            new RunOnceExEnumerator(),
            new SecurityProvidersEnumerator(),
            new JustInTimeDebuggerEnumerator(),
            new PowerShellProfileEnumerator(),
            new ProfilerInjectionEnumerator(),
        };

    /// <summary>
    /// Enumerates every autostart item across all surfaces, newest-surface-first in
    /// registration order. Enumerator failures are isolated per surface.
    /// </summary>
    public IReadOnlyList<AutostartEntry> Scan(CancellationToken cancellationToken = default) =>
        ScanWithCoverage(cancellationToken).Entries;

    /// <summary>
    /// The same scan, plus what it was not allowed to read.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="Scan"/> so every existing caller is unaffected, but this is the
    /// honest one. A scan that quietly returns fewer rows because Windows refused it is
    /// indistinguishable from a clean machine, and on a real desktop that difference was 210
    /// autostart items including one already flagged as suspicious.
    /// </remarks>
    public PersistenceScanResult ScanWithCoverage(CancellationToken cancellationToken = default)
    {
        // 1. Collect raw autostart records, isolating a failing surface. The token is
        //    checked between surfaces (each is a fast registry/WMI read) and drives the
        //    signature batch below, so a scan can be aborted promptly.
        var raws = new List<RawAutostart>();
        var unreadableLocations = 0;
        var unreadableSurfaces = new List<string>();
        foreach (var enumerator in _enumerators)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                raws.AddRange(enumerator.Enumerate());
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException
                                         or System.Security.SecurityException
                                         or IOException)
            {
                // Isolate a failing surface — the rest of the scan proceeds — but say so. A surface
                // that threw contributed nothing at all, which is the largest blind spot of the two
                // and used to be completely invisible.
                unreadableSurfaces.Add(enumerator.Surface);
                continue;
            }
            // Read after the enumeration is fully consumed, which is the contract on the member.
            if (enumerator.UnreadableLocations is var skipped and > 0)
            {
                unreadableLocations += skipped;
                unreadableSurfaces.Add(enumerator.Surface);
            }
        }

        // 2. Resolve each record's executable, then verify every distinct file through the
        //    in-process WinTrust/catalog verifier. No PowerShell child process or online
        //    revocation lookup is involved.
        var resolved = raws
            .Select(r => (Raw: r, Resolution: CommandLine.ResolveExecutable(r.Command)))
            .ToList();
        var verdicts = _verifier.VerifyMany(
            resolved.Where(x => x.Resolution.ImagePath is not null)
                .Select(x => x.Resolution.ImagePath!).ToList(),
            cancellationToken);

        // 3. Assemble. Version resources are read once per distinct image: a report holds thousands
        //    of entries and a few hundred distinct files, so caching turns a per-entry Win32 call
        //    into a per-file one.
        var originalNames = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var results = new List<AutostartEntry>(resolved.Count);
        foreach (var (raw, resolution) in resolved)
        {
            var image = resolution.ImagePath;
            var verdict = image is not null && verdicts.TryGetValue(image, out var v)
                ? v
                : SignatureVerdict.Missing;
            results.Add(new AutostartEntry(
                raw.Vector,
                raw.Name,
                raw.Location,
                raw.Command,
                image,
                resolution.ExpectedPath,
                resolution.Status,
                verdict,
                OriginalFileNameOf(image, originalNames)));
        }
        return new PersistenceScanResult(
            results,
            new PersistenceCoverage(unreadableLocations, unreadableSurfaces));
    }

    /// <summary>
    /// The name the vendor compiled into an image, or null when there is none to read.
    /// </summary>
    /// <remarks>
    /// Read here rather than in the triage rule, because this is already the step that touches
    /// every resolved file and the rule itself runs repeatedly while a report is assembled and must
    /// perform no I/O. Any failure yields null: an unreadable version resource is not evidence of
    /// anything, and the file-name path still applies.
    /// </remarks>
    private static string? OriginalFileNameOf(string? image, Dictionary<string, string?> cache)
    {
        if (string.IsNullOrWhiteSpace(image))
        {
            return null;
        }
        if (cache.TryGetValue(image, out var cached))
        {
            return cached;
        }
        var name = ReadOriginalFileName(image);
        cache[image] = name;
        return name;
    }

    private static string? ReadOriginalFileName(string image)
    {
        try
        {
            var name = System.Diagnostics.FileVersionInfo.GetVersionInfo(image).OriginalFilename;
            return string.IsNullOrWhiteSpace(name) ? null : name;
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or ArgumentException)
        {
            return null;
        }
    }
}

/// <summary>What a scan was not allowed to read, so "no findings" can be told apart from
/// "not allowed to look".</summary>
/// <param name="UnreadableLocations">
/// Individual definitions skipped — a task file, a key — that the scan could not open.
/// </param>
/// <param name="UnreadableSurfaces">
/// The surfaces those came from, plus any surface that failed outright and contributed nothing.
/// </param>
public sealed record PersistenceCoverage(
    int UnreadableLocations,
    IReadOnlyList<string> UnreadableSurfaces)
{
    /// <summary>A scan that saw everything it looked for.</summary>
    public static readonly PersistenceCoverage Complete = new(0, Array.Empty<string>());

    /// <summary>True when something was skipped, whatever the reason.</summary>
    public bool IsPartial => UnreadableLocations > 0 || UnreadableSurfaces.Count > 0;
}

/// <summary>A scan and the honest account of its own coverage.</summary>
public sealed record PersistenceScanResult(
    IReadOnlyList<AutostartEntry> Entries,
    PersistenceCoverage Coverage);
