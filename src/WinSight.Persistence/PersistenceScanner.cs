using WinSight.Core;

namespace WinSight.Persistence;

/// <summary>
/// KnockKnock-class scanner: sweeps every registered autostart surface, resolves each
/// item's on-disk executable, and attaches its Authenticode verdict. Read-only — it
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
        };

    /// <summary>
    /// Enumerates every autostart item across all surfaces, newest-surface-first in
    /// registration order. Enumerator failures are isolated per surface.
    /// </summary>
    public IReadOnlyList<AutostartEntry> Scan()
    {
        // 1. Collect raw autostart records, isolating a failing surface.
        var raws = new List<RawAutostart>();
        foreach (var enumerator in _enumerators)
        {
            try
            {
                raws.AddRange(enumerator.Enumerate());
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException
                                         or System.Security.SecurityException
                                         or IOException)
            {
                // isolate a failing surface — the rest of the scan proceeds
            }
        }

        // 2. Resolve each record's executable, then verify EVERY signature in one
        //    batch (a single Get-AuthenticodeSignature call, not one process per item).
        var resolved = raws
            .Select(r => (Raw: r, Image: CommandLine.ExtractExecutable(r.Command)))
            .ToList();
        var verdicts = _verifier.VerifyMany(
            resolved.Where(x => x.Image is not null).Select(x => x.Image!).ToList());

        // 3. Assemble.
        var results = new List<AutostartEntry>(resolved.Count);
        foreach (var (raw, image) in resolved)
        {
            var verdict = image is not null && verdicts.TryGetValue(image, out var v)
                ? v
                : SignatureVerdict.Missing;
            results.Add(new AutostartEntry(raw.Vector, raw.Name, raw.Location, raw.Command, image, verdict));
        }
        return results;
    }
}
