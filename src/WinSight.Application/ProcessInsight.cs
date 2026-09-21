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
/// Its loaded modules, flagged ones first (unsigned, or trusted only through a user-installed root).
/// A busy process loads hundreds and all but a handful are Microsoft-signed, so load order would
/// bury the one worth seeing.
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

    /// <summary>Loaded modules whose signature holds only through a user-installed root.</summary>
    public int UserRootModuleCount => Modules.Count(module => module.TrustedOnlyThroughUserRoot);

    /// <summary>Live sockets to an off-box, routable destination.</summary>
    public int EstablishedExternalCount => Connections.Count(IsEstablishedExternal);

    /// <summary>
    /// Whether this process is worth an operator's attention, by the same rules the individual
    /// scanners already use — so the drill-down never disagrees with the list it was opened from.
    /// </summary>
    public bool IsNotable =>
        Process.Flagged || Modules.Any(module => module.Flagged) || EstablishedExternalCount > 0;

    internal static bool IsEstablishedExternal(Connection connection) =>
        connection.External
        && connection.State.Equals("ESTABLISHED", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Coverage gaps encountered while gathering a per-process drill-down.</summary>
public sealed record ProcessInsightCoverage(
    int UnreadableProcessSources,
    int UnreadableProcessItems,
    int UnreadableModuleSources,
    int UnreadableModuleItems)
{
    public bool IsComplete =>
        UnreadableProcessSources == 0 &&
        UnreadableProcessItems == 0 &&
        UnreadableModuleSources == 0 &&
        UnreadableModuleItems == 0;

    public static ProcessInsightCoverage From(
        AcquisitionSnapshot<ProcessInfo> processes,
        AcquisitionSnapshot<LoadedModule>? modules = null)
    {
        ArgumentNullException.ThrowIfNull(processes);
        return new ProcessInsightCoverage(
            processes.UnreadableSources,
            processes.UnreadableItems,
            modules?.UnreadableSources ?? 0,
            modules?.UnreadableItems ?? 0);
    }
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
/// taken seconds apart, so they disagree routinely and Windows may recycle a PID between them. Rows
/// are joined only when PID and process creation time both match. Missing identity evidence excludes
/// the row rather than attributing it to whichever process currently owns the same number.
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

        var process = processes
            .Where(candidate => candidate.Pid == pid)
            .OrderByDescending(candidate => candidate.StartTimestampUtcTicks ?? long.MinValue)
            .FirstOrDefault();
        if (process is null)
        {
            return null;
        }

        return new ProcessInsight(
            process,
            FindParent(process, processes),
            FindChildren(process, processes),
            RankModules(process, modules),
            RankConnections(process, connections));
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
    private static ProcessInfo? FindParent(ProcessInfo process, IReadOnlyList<ProcessInfo> processes)
    {
        if (process.ParentPid == process.Pid || process.StartTimestampUtcTicks is not { } childStart)
        {
            return null;
        }

        return processes
            .Where(candidate =>
                candidate.Pid == process.ParentPid
                && candidate.StartTimestampUtcTicks is { } parentStart
                && parentStart <= childStart)
            .OrderByDescending(candidate => candidate.StartTimestampUtcTicks)
            .FirstOrDefault();
    }

    private static ProcessInfo[] FindChildren(
        ProcessInfo process,
        IReadOnlyList<ProcessInfo> processes) =>
        process.StartTimestampUtcTicks is not { } parentStart
            ? []
            : processes
            .Where(candidate =>
                candidate.ParentPid == process.Pid
                && candidate.Pid != process.Pid
                && candidate.StartTimestampUtcTicks is { } childStart
                && childStart >= parentStart)
            .OrderBy(candidate => candidate.Pid)
            .ToArray();

    /// <summary>Flagged first, then by name so two runs of one snapshot render identically.</summary>
    private static LoadedModule[] RankModules(
        ProcessInfo process,
        IReadOnlyList<LoadedModule> modules) =>
        modules
            .Where(module =>
                module.Pid == process.Pid
                && StableIdentityMatches(
                    process.StartTimestampUtcTicks,
                    module.ProcessStartTimestampUtcTicks))
            .OrderByDescending(module => module.Flagged)
            .ThenBy(module => module.ModuleName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(module => module.ModuleName, StringComparer.Ordinal)
            .ToArray();

    /// <summary>Live external sockets first: they are why this view gets opened.</summary>
    private static Connection[] RankConnections(
        ProcessInfo process,
        IReadOnlyList<Connection> connections) =>
        connections
            .Where(connection =>
                connection.Pid == process.Pid
                && StableIdentityMatches(
                    process.StartTimestampUtcTicks,
                    connection.ProcessStartTimestampUtcTicks))
            .OrderByDescending(ProcessInsight.IsEstablishedExternal)
            .ThenBy(connection => connection.Remote, StringComparer.OrdinalIgnoreCase)
            .ThenBy(connection => connection.Remote, StringComparer.Ordinal)
            .ToArray();

    private static bool StableIdentityMatches(long? left, long? right) =>
        left is not null && left == right;
}
