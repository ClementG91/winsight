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
        var verifier = new CachingSignatureVerifier(new NativeSignatureVerifier());
        var scanner = new PersistenceScanner(enumerators, verifier);
        var source = CompositePersistenceChangeSource.ForEnumerators(enumerators);
        return new PersistenceMonitor(source, scanner.Scan, baselineStore: new FilePersistenceBaselineStore());
    }
}
