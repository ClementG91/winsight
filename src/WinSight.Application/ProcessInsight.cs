using WinSight.Core;
using WinSight.Modules;
using WinSight.NetMonitor;
using WinSight.Processes;

namespace WinSight.Application;

/// <summary>
/// Everything WinSight knows about one running process, gathered into a single answer.
/// </summary>
/// <param name="Process">The process itself, as the process scan reported it.</param>
/// <param name="Parent">
/// Its parent, or null when that process is no longer running — which is the normal outcome for
/// anything launched by an installer or a script that has since finished, and is itself worth
/// knowing. <see cref="ProcessInfo.ParentPid"/> on <paramref name="Process"/> still names it.
/// </param>
/// <param name="Children">Processes that name this one as their parent, ordered by pid.</param>
/// <param name="Modules">
/// Its loaded modules, unsigned ones first. A busy process loads hundreds and all but a handful are
/// Microsoft-signed, so load order would bury the one worth seeing.
/// </param>
/// <param name="Connections">Its sockets, external and established ones first.</param>
public sealed record ProcessInsight(
    ProcessInfo Process,
    ProcessInfo? Parent,
    IReadOnlyList<ProcessInfo> Children,
    IReadOnlyList<LoadedModule> Modules,
    IReadOnlyList<Connection> Connections)
{
    /// <summary>Loaded modules whose file is unsigned or untrusted.</summary>
    public int UnsignedModuleCount => Modules.Count(module => module.Unsigned);

    /// <summary>Live sockets to an off-box, routable destination.</summary>
    public int EstablishedExternalCount => Connections.Count(IsEstablishedExternal);

    /// <summary>
    /// Whether this process is worth an operator's attention, by the same rules the individual
    /// scanners already use — so the drill-down never disagrees with the list it was opened from.
    /// </summary>
    public bool IsNotable =>
        Process.Unsigned || UnsignedModuleCount > 0 || EstablishedExternalCount > 0;

    internal static bool IsEstablishedExternal(Connection connection) =>
        connection.External
        && connection.State.Equals("ESTABLISHED", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Joins the process, module and connection snapshots into a single per-process view.
/// </summary>
/// <remarks>
/// <b>Why this is a pure function and not a scanner.</b> The data is already gathered; what was
/// missing is the pivot. Keeping the join free of acquisition means every decision it makes — what
/// counts as this process's parent, what is worth surfacing out of hundreds of modules, what to do
/// when the snapshots disagree — is exercised by tests instead of by whatever happens to be running.
///
/// <b>The snapshots are not atomic.</b> Processes, modules and connections are three separate scans
/// taken seconds apart, so they disagree routinely: a module can name a pid that has since exited,
/// and a process can appear that had no modules read. Neither is an error. The join is built on what
/// is consistent and never throws on the rest — a drill-down that fails because a process exited
/// mid-scan would fail exactly when a short-lived process is the thing being investigated.
/// </remarks>
public static class ProcessInsightBuilder
{
    /// <summary>
    /// The insight for <paramref name="pid"/>, or null when no process snapshot names it.
    /// </summary>
    /// <remarks>
    /// Null rather than an empty record on purpose. A hollow insight renders as a process that
    /// exists and has nothing loaded and nothing connected — a confident description of something
    /// that is not running. "Never heard of this pid" and "this pid is idle" are different answers.
    /// </remarks>
    public static ProcessInsight? Build(
        int pid,
        IReadOnlyList<ProcessInfo> processes,
        IReadOnlyList<LoadedModule> modules,
        IReadOnlyList<Connection> connections)
    {
        // An empty list means "nothing found"; a null means the caller has a bug. Collapsing them
        // would report a process with no modules when the module scan never ran at all.
        ArgumentNullException.ThrowIfNull(processes);
        ArgumentNullException.ThrowIfNull(modules);
        ArgumentNullException.ThrowIfNull(connections);

        var process = processes.FirstOrDefault(candidate => candidate.Pid == pid);
        if (process is null)
        {
            return null;
        }

        return new ProcessInsight(
            process,
            FindParent(process, processes),
            FindChildren(pid, processes),
            RankModules(pid, modules),
            RankConnections(pid, connections));
    }

    /// <summary>
    /// The parent process, excluding the process itself.
    /// </summary>
    /// <remarks>
    /// The self-reference guard is not hypothetical: the System Idle Process reports pid 0 with
    /// parent 0, and the process reader falls back to 0 for a row whose id it could not read. A tree
    /// built from an unguarded lookup recurses forever, and a lineage line says a process launched
    /// itself.
    /// </remarks>
    private static ProcessInfo? FindParent(ProcessInfo process, IReadOnlyList<ProcessInfo> processes) =>
        process.ParentPid == process.Pid
            ? null
            : processes.FirstOrDefault(candidate => candidate.Pid == process.ParentPid);

    private static ProcessInfo[] FindChildren(int pid, IReadOnlyList<ProcessInfo> processes) =>
        processes
            .Where(candidate => candidate.ParentPid == pid && candidate.Pid != pid)
            .OrderBy(candidate => candidate.Pid)
            .ToArray();

    /// <summary>Unsigned first, then by name so two runs of one snapshot render identically.</summary>
    private static LoadedModule[] RankModules(int pid, IReadOnlyList<LoadedModule> modules) =>
        modules
            .Where(module => module.Pid == pid)
            .OrderByDescending(module => module.Unsigned)
            .ThenBy(module => module.ModuleName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(module => module.ModuleName, StringComparer.Ordinal)
            .ToArray();

    /// <summary>Live external sockets first: they are why this view gets opened.</summary>
    private static Connection[] RankConnections(int pid, IReadOnlyList<Connection> connections) =>
        connections
            .Where(connection => connection.Pid == pid)
            .OrderByDescending(ProcessInsight.IsEstablishedExternal)
            .ThenBy(connection => connection.Remote, StringComparer.OrdinalIgnoreCase)
            .ThenBy(connection => connection.Remote, StringComparer.Ordinal)
            .ToArray();
}
