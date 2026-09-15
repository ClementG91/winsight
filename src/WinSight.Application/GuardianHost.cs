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
        PersistenceScanResult Scan(IReadOnlyList<IAutostartEnumerator> surfaces, CancellationToken ct) =>
            new PersistenceScanner(surfaces, verifier).ScanWithCoverage(ct);
        var source = CompositePersistenceChangeSource.ForEnumerators(enumerators);
        return new PersistenceMonitor(enumerators, source, Scan, baselineStore: new FilePersistenceBaselineStore());
    }

    /// <summary>
    /// Guardian's real state. It is meant to run for the whole session, so a start that failed is a
    /// failed monitor rather than an "off" one; while the initial scan is still running nothing has
    /// been armed yet and it reads as off.
    /// </summary>
    public static MonitorHealth Health(bool started, bool startFailed, (int Requested, int Armed) coverage) =>
        Health(started, startFailed, coverage, diagnostics: null);

    /// <summary>
    /// As above, and a running monitor with an undelivered arrival or an unrecovered scan or save is
    /// partial: it is watching, but not everything it saw has reached the operator or been persisted.
    /// </summary>
    public static MonitorHealth Health(
        bool started, bool startFailed, (int Requested, int Armed) coverage,
        PersistenceMonitorDiagnostics? diagnostics) =>
        started
            ? MonitorHealth.For("Guardian", enabled: true, coverage.Armed, coverage.Requested,
                lostObservations: diagnostics?.IsDegraded == true)
            : MonitorHealth.For("Guardian", enabled: startFailed, armed: 0,
                requested: Math.Max(1, coverage.Requested));

    /// <summary>
    /// One culture-independent diagnostic line for the protection tooltip, or null when Guardian has
    /// nothing pending, unrecovered or unlisted.
    /// </summary>
    public static string? DiagnosticsLine(PersistenceMonitorDiagnostics diagnostics)
    {
        ArgumentNullException.ThrowIfNull(diagnostics);
        var parts = new List<string>();
        if (diagnostics.PendingNotifications > 0)
        {
            parts.Add($"{diagnostics.PendingNotifications} undelivered alert(s)"
                + (diagnostics.AutomaticRetriesExhausted ? ", automatic retries stopped" : string.Empty));
        }
        if (diagnostics.IsDegraded && diagnostics.LastFault is { } fault)
        {
            parts.Add($"last fault {fault.Operation}: {fault.Exception.GetType().Name}");
        }
        if (diagnostics.UnlistedArrivals > 0)
        {
            parts.Add($"{diagnostics.UnlistedArrivals} arrival(s) reported but not kept in the in-app list");
        }
        return parts.Count == 0 ? null : "Guardian: " + string.Join("; ", parts);
    }

    /// <summary>Whether the operator can usefully ask Guardian to retry now.</summary>
    public static bool CanRetry(PersistenceMonitorDiagnostics diagnostics) =>
        diagnostics.IsDegraded || diagnostics.AutomaticRetriesExhausted;

    /// <summary>A journal line for a contained monitor failure, bounded and free of stack traces.</summary>
    public static SecurityAlert FaultAlert(PersistenceMonitorFault fault)
    {
        ArgumentNullException.ThrowIfNull(fault);
        var message = fault.Exception.Message.ReplaceLineEndings(" ");
        if (message.Length > 300)
        {
            message = message[..300];
        }
        return new SecurityAlert(fault.AtUtc.ToLocalTime(), "Guardian", "MonitorFault",
            $"{fault.Operation}: {fault.Exception.GetType().Name}: {message}");
    }
}
