using WinSight.Modules;
using WinSight.NetMonitor;
using WinSight.Processes;
using WinSight.Reporting;

namespace WinSight.Application;

public static partial class Adapters
{
    public static ToolReport Processes(bool flaggedOnly, CancellationToken cancellationToken = default)
    {
        var acquisition = new ProcessLister(SharedVerifier).SnapshotWithCoverage(cancellationToken);
        var procs = acquisition.Items;
        var b = new ToolReport.Builder("processes");
        foreach (var p in procs.Where(p => !flaggedOnly || p.Flagged)
                     .OrderByDescending(p => p.Flagged).ThenBy(p => p.Name, StringComparer.OrdinalIgnoreCase))
        {
            b.Add(
                p.Flagged ? Severity.Notable : Severity.Info,
                $"{p.Name} (pid {p.Pid})",
                WithUserRootNote(p.Path ?? "<no image>", p.TrustedOnlyThroughUserRoot),
                new Dictionary<string, string?>
                {
                    ["pid"] = p.Pid.ToString(),
                    ["name"] = p.Name,
                    ["path"] = p.Path,
                    ["parentPid"] = p.ParentPid.ToString(),
                    ["commandLine"] = p.CommandLine,
                    ["signature"] = p.Signature.State.ToString(),
                    ["signer"] = p.Signature.Signer,
                    ["userInstalledTrust"] = p.TrustedOnlyThroughUserRoot ? "true" : null,
                    ["microsoftSigned"] = MicrosoftSignedField(p.Signature),
                });
        }
        AddCoverageFinding(b, acquisition);
        AddSignatureCoverageFinding(
            b, procs.Where(process => process.Path is not null).Select(process => process.Signature));
        return b.Build(
            $"{procs.Count} process(es), {procs.Count(p => p.Unsigned)} unsigned"
            + UserRootSuffix(procs.Count(p => p.TrustedOnlyThroughUserRoot))
            + CoverageSuffix(acquisition));
    }

    /// <summary>
    /// Everything WinSight knows about one process, gathered into a single view.
    /// </summary>
    /// <remarks>
    /// The acquisition edge for the per-process drill-down: it takes the three snapshots and hands
    /// them to a pure pivot, so every decision about what the answer means is unit-tested and this
    /// method stays a thin gather-and-render.
    ///
    /// Modules are read for the one process only. The full module sweep costs 57 seconds on a real
    /// desktop, which is a fine price for "what is loaded anywhere on this machine" and an absurd
    /// one for a view opened on a single pid.
    /// </remarks>
    public static ToolReport ProcessDrillDown(int pid, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var processAcquisition = new ProcessLister(SharedVerifier).SnapshotWithCoverage(cancellationToken);
        var processes = processAcquisition.Items;

        // Established first, before paying for anything else. A pid that is not running produces
        // the same "not running" answer whatever the other two scans return, and making someone
        // wait through a full connection sweep to be told that is simply rude. Measured: the absent
        // case drops from ~15 s to ~7 s.
        if (!processes.Any(process => process.Pid == pid))
        {
            return ProcessInsightReport.Render(
                pid,
                insight: null,
                ProcessInsightCoverage.From(processAcquisition));
        }

        var moduleAcquisition = new ModuleLister(SharedVerifier).SnapshotForWithCoverage(pid, cancellationToken);
        var modules = moduleAcquisition.Items;
        var connections = new ConnectionMonitor(SharedVerifier).Snapshot(cancellationToken);

        return ProcessInsightReport.Render(
            pid,
            ProcessInsightBuilder.Build(pid, processes, modules, connections),
            ProcessInsightCoverage.From(processAcquisition, moduleAcquisition));
    }

    public static ToolReport Modules(bool flaggedOnly, CancellationToken cancellationToken = default)
    {
        var acquisition = new ModuleLister(SharedVerifier).SnapshotWithCoverage(cancellationToken);
        var modules = acquisition.Items;
        var flagged = modules.Where(m => m.Flagged).ToList();
        var b = new ToolReport.Builder("modules");
        // The security signal is an unsigned/untrusted DLL loaded into a running
        // process (injection / search-order hijack), or one whose signature holds only
        // through a root the user could have installed. Listing every loaded module would
        // be pure noise, so items are the flagged modules; the summary carries totals.
        // (`--flagged` is implied here, the tool only ever reports notable modules.)
        _ = flaggedOnly;
        foreach (var m in flagged
                     .OrderBy(m => m.ProcessName, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(m => m.ModuleName, StringComparer.OrdinalIgnoreCase))
        {
            b.Add(
                Severity.Notable,
                $"{m.ProcessName} (pid {m.Pid}) ← {m.ModuleName}",
                WithUserRootNote(m.Path ?? "<unknown>", m.TrustedOnlyThroughUserRoot),
                new Dictionary<string, string?>
                {
                    ["pid"] = m.Pid.ToString(),
                    ["process"] = m.ProcessName,
                    ["module"] = m.ModuleName,
                    ["path"] = m.Path,
                    ["signature"] = m.Signature.State.ToString(),
                    ["signer"] = m.Signature.Signer,
                    ["userInstalledTrust"] = m.TrustedOnlyThroughUserRoot ? "true" : null,
                    ["microsoftSigned"] = MicrosoftSignedField(m.Signature),
                });
        }
        AddCoverageFinding(b, acquisition);
        AddSignatureCoverageFinding(
            b, modules.Where(module => module.Path is not null).Select(module => module.Signature));
        var processCount = modules.Select(m => m.Pid).Distinct().Count();
        return b.Build(
            $"{modules.Count} loaded module(s) across {processCount} process(es), {flagged.Count(m => m.Unsigned)} unsigned"
            + UserRootSuffix(flagged.Count(m => m.TrustedOnlyThroughUserRoot))
            + CoverageSuffix(acquisition));
    }
}
