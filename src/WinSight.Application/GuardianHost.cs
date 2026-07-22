using WinSight.Core;
using WinSight.Persistence;

namespace WinSight.Application;

/// <summary>
/// Assembles a ready-to-run persistence monitor (Guardian) over the default autostart surfaces: a
/// composite registry + filesystem change source feeding the pure monitor core, with re-scans backed
/// by the same <see cref="PersistenceScanner"/> the on-demand scan uses. One call the dashboard hosts
/// while it is running.
/// </summary>
public static class GuardianHost
{
    /// <summary>
    /// Builds a monitor over the default enumerators. It does no work until <see cref="PersistenceMonitor.Start"/>
    /// is called, which seeds the baseline from one full scan (silently) and begins listening.
    /// </summary>
    public static PersistenceMonitor CreateDefault()
    {
        var enumerators = PersistenceScanner.DefaultEnumerators();
        // Use the same robust, cached verifier the on-demand scan uses: WinVerifyTrust with a
        // catalog fallback (so signed OS binaries read as trusted, not "unknown"), and caching so a
        // full re-scan on every change does not re-verify unchanged binaries each time.
        //
        // Content verification is on here and off in the one-shot scans, because Guardian is the
        // case the cheap fingerprint is wrong for. It runs for days, so a verdict cached against
        // length and timestamps alone could be served long after the file behind it was swapped —
        // and Guardian's verdicts are shown beside persistence alerts, which is the worst place for
        // a stale "signed". The cost is ~1.6 ms per lookup against ~19 ms for the verification it
        // still avoids, and Guardian re-scans only the surface that changed, so the volume is small.
        var verifier = new CachingSignatureVerifier(
            new NativeSignatureVerifier(), verifyContent: true);
        // Scan exactly the given surface subset, so a change re-scans only what actually changed.
        IReadOnlyList<AutostartEntry> Scan(IReadOnlyList<IAutostartEnumerator> surfaces, CancellationToken ct) =>
            new PersistenceScanner(surfaces, verifier).Scan(ct);
        var source = CompositePersistenceChangeSource.ForEnumerators(enumerators);
        return new PersistenceMonitor(enumerators, source, Scan, baselineStore: new FilePersistenceBaselineStore());
    }
}
