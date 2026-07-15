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
        _verifier = verifier ?? new AuthenticodeVerifier();
    }

    /// <summary>The autostart surfaces covered by a default scan (Phase 1).</summary>
    public static IReadOnlyList<IAutostartEnumerator> DefaultEnumerators() =>
        new IAutostartEnumerator[]
        {
            new RunKeyEnumerator(),
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
            new ShimDatabaseEnumerator(),
        };

    /// <summary>
    /// Enumerates every autostart item across all surfaces, newest-surface-first in
    /// registration order. Enumerator failures are isolated per surface.
    /// </summary>
    public IReadOnlyList<AutostartEntry> Scan(CancellationToken cancellationToken = default)
    {
        // 1. Collect raw autostart records, isolating a failing surface. The token is
        //    checked between surfaces (each is a fast registry/WMI read) and drives the
        //    signature batch below, so a scan can be aborted promptly.
        var raws = new List<RawAutostart>();
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
                // isolate a failing surface, the rest of the scan proceeds
            }
        }

        // 2. Resolve each record's executable, then verify EVERY signature in one
        //    batch (a single Get-AuthenticodeSignature call, not one process per item).
        var resolved = raws
            .Select(r => (Raw: r, Resolution: CommandLine.ResolveExecutable(r.Command)))
            .ToList();
        var verdicts = _verifier.VerifyMany(
            resolved.Where(x => x.Resolution.ImagePath is not null)
                .Select(x => x.Resolution.ImagePath!).ToList(),
            cancellationToken);

        // 3. Assemble.
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
                verdict));
        }
        return results;
    }
}
