using WinSight.Core;
using WinSight.Modules;
using WinSight.NetMonitor;
using WinSight.Processes;
using WinSight.Reporting;

namespace WinSight.Application;

/// <summary>Owns the ordered acquisition boundary of the per-process report.</summary>
internal sealed class ProcessInsightAcquirer(IProcessInsightAcquisition acquisition)
{
    private readonly IProcessInsightAcquisition _acquisition = acquisition ?? throw new ArgumentNullException(nameof(acquisition));

    internal ToolReport Acquire(int pid, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (pid >= 0)
        {
            // Only a completed lookup of this PID can establish its absence independently
            // of unreadable rows elsewhere. A gap remains unknown, never an absent process.
            var targetAcquisition = _acquisition.AcquireTargetProcess(pid, cancellationToken);
            if (!targetAcquisition.Items.Any(process => process.Pid == pid))
            {
                return ProcessInsightReport.Render(
                    pid,
                    insight: null,
                    ProcessInsightCoverage.From(targetAcquisition));
            }
        }

        // A positive lookup is admission only. Use the later full snapshot for every identity
        // and lineage decision; a recycled PID must not inherit the initial process metadata.
        var processAcquisition = _acquisition.GetProcesses(cancellationToken);
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

        var moduleAcquisition = _acquisition.GetModules(pid, cancellationToken);
        var modules = moduleAcquisition.Items;
        var connections = _acquisition.GetConnections(cancellationToken);

        return ProcessInsightReport.Render(
            pid,
            ProcessInsightBuilder.Build(pid, processes, modules, connections),
            ProcessInsightCoverage.From(processAcquisition, moduleAcquisition));
    }
}

internal interface IProcessInsightAcquisition
{
    AcquisitionSnapshot<ProcessInfo> AcquireTargetProcess(int pid, CancellationToken cancellationToken);
    AcquisitionSnapshot<ProcessInfo> GetProcesses(CancellationToken cancellationToken);
    AcquisitionSnapshot<LoadedModule> GetModules(int pid, CancellationToken cancellationToken);
    IReadOnlyList<Connection> GetConnections(CancellationToken cancellationToken);
}

/// <summary>Creates each native scanner only when that stage is requested.</summary>
internal sealed class NativeProcessInsightAcquisition(ISignatureVerifier verifier) : IProcessInsightAcquisition
{
    private readonly ISignatureVerifier _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));

    public AcquisitionSnapshot<ProcessInfo> AcquireTargetProcess(int pid, CancellationToken cancellationToken) =>
        new ProcessLister(_verifier).SnapshotForWithCoverage(pid, cancellationToken);

    public AcquisitionSnapshot<ProcessInfo> GetProcesses(CancellationToken cancellationToken) =>
        new ProcessLister(_verifier).SnapshotWithCoverage(cancellationToken);

    public AcquisitionSnapshot<LoadedModule> GetModules(int pid, CancellationToken cancellationToken) =>
        new ModuleLister(_verifier).SnapshotForWithCoverage(pid, cancellationToken);

    public IReadOnlyList<Connection> GetConnections(CancellationToken cancellationToken) =>
        new ConnectionMonitor(_verifier).Snapshot(cancellationToken);
}
