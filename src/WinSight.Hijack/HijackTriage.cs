namespace WinSight.Hijack;

/// <summary>What kind of pre-emption a finding describes.</summary>
public enum HijackKind
{
    /// <summary>An unquoted service command line: an earlier path is tried first.</summary>
    UnquotedServicePath,

    /// <summary>
    /// A service's own directory is writable. Windows searches it first for every DLL the service
    /// loads, and the executable itself sits there.
    /// </summary>
    WritableServiceDirectory,

    /// <summary>
    /// A machine-wide PATH directory is writable, or absent and creatable. Anything resolved by
    /// name rather than by full path can be answered from it.
    /// </summary>
    WritablePathEntry,

    /// <summary>
    /// A program imports a DLL that no directory in its search order provides. The slot is
    /// permanently unoccupied, so whoever can write that name into a searched directory is loaded
    /// into the program at its privilege, every time it runs.
    /// </summary>
    PhantomImport,
}

/// <summary>How exposed a finding actually is on this machine.</summary>
public enum HijackExposure
{
    /// <summary>Structurally pre-emptable, but nothing an unprivileged user can act on.</summary>
    Latent,

    /// <summary>An unprivileged user could plant the file right now.</summary>
    Exploitable,

    /// <summary>
    /// The pre-empting file already exists. Either the machine is already hijacked, or a legitimate
    /// program happens to sit there — both are worth a human look immediately.
    /// </summary>
    Occupied,
}

/// <summary>Something that could be run in place of what the machine intended.</summary>
/// <param name="Kind">Which pre-emption this is.</param>
/// <param name="Subject">The service name, or the directory, the finding is about.</param>
/// <param name="Context">The registered command line, or where the directory came from.</param>
/// <param name="Exposure">How exposed it is in practice.</param>
/// <param name="Candidates">
/// For an unquoted path, every path Windows would try first, in order. Empty for the other kinds,
/// where the subject is itself the plantable location.
/// </param>
/// <param name="ActionablePath">
/// The specific path that makes this exploitable or occupied — the one to go and look at. Null when
/// the finding is latent.
/// </param>
public sealed record HijackFinding(
    HijackKind Kind,
    string Subject,
    string Context,
    HijackExposure Exposure,
    IReadOnlyList<string> Candidates,
    string? ActionablePath);

/// <summary>
/// Turns pre-emptable configurations into findings ranked by whether they can actually be exploited.
/// </summary>
/// <remarks>
/// <b>Why exposure is graded rather than everything being flagged.</b> Unquoted service paths are
/// common on Windows — plenty of vendors ship them — and almost all of them sit under
/// <c>C:\Program Files</c>, where an unprivileged user cannot create the earlier candidate.
/// Flagging all of them equally produces a wall of items nobody reads, and the two that matter are
/// lost in it. The grade is decided by asking the filesystem, not by pattern-matching the path:
/// whether a directory is writable is a fact about this machine, and a machine with loosened
/// permissions on <c>C:\</c> is exactly the one that needs telling.
///
/// <b>The directory checks report nothing on a healthy machine, by design.</b> Measured on a real
/// desktop: 18 machine PATH entries and 88 auto-starting services, none of them writable. A check
/// whose normal output is silence is the right shape here — when it does speak, it means something.
/// </remarks>
public sealed class HijackTriage(IWritabilityProbe? probe = null)
{
    private readonly IWritabilityProbe _probe = probe ?? new WritabilityProbe();

    /// <summary>
    /// The finding for one service's command line, or null when it is not pre-emptable this way.
    /// </summary>
    public HijackFinding? AssessCommandLine(string service, string? commandLine)
    {
        var candidates = UnquotedPath.HijackCandidates(commandLine);
        if (candidates.Count == 0)
        {
            return null;
        }

        // An existing candidate outranks a writable one: the file is already there, so the question
        // is no longer whether someone could plant it.
        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate))
            {
                return new HijackFinding(
                    HijackKind.UnquotedServicePath, service, commandLine!,
                    HijackExposure.Occupied, candidates, candidate);
            }
        }

        foreach (var candidate in candidates)
        {
            if (_probe.CanCreate(candidate))
            {
                return new HijackFinding(
                    HijackKind.UnquotedServicePath, service, commandLine!,
                    HijackExposure.Exploitable, candidates, candidate);
            }
        }

        return new HijackFinding(
            HijackKind.UnquotedServicePath, service, commandLine!,
            HijackExposure.Latent, candidates, ActionablePath: null);
    }

    /// <summary>
    /// The finding for a service whose own directory can be written to, or null when it cannot.
    /// </summary>
    /// <remarks>
    /// A program's own directory is the <i>first</i> place Windows looks for every DLL it loads, so
    /// a writable one lets an attacker answer any of those imports — and replace the executable
    /// besides. For a service that means SYSTEM, at boot. Only writable directories are reported:
    /// listing the other eighty-seven would bury this one.
    /// </remarks>
    public HijackFinding? AssessServiceDirectory(string service, string? directory)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            return null;
        }
        // The name is arbitrary; the question is whether *any* file can be created here, since the
        // attacker chooses the DLL name to match whatever the service imports.
        var planted = Path.Combine(directory, "winsight-probe.dll");
        return _probe.CanCreate(planted)
            ? new HijackFinding(
                HijackKind.WritableServiceDirectory, service, directory,
                HijackExposure.Exploitable, [], directory)
            : null;
    }

    /// <summary>
    /// The finding for a machine-wide PATH directory anyone could plant into, or null when there is
    /// nothing to say about it.
    /// </summary>
    /// <remarks>
    /// A writable PATH directory is a hijack point for <i>every</i> process that resolves anything
    /// by name rather than by full path. An <i>absent</i> one whose parent is writable is the same
    /// vulnerability one step earlier: create the directory, then fill it. Both are reported;
    /// an absent entry whose parent is also closed is just stale configuration and stays quiet.
    /// </remarks>
    public HijackFinding? AssessPathEntry(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            return null;
        }

        if (Directory.Exists(directory))
        {
            return _probe.CanCreate(Path.Combine(directory, "winsight-probe.dll"))
                ? new HijackFinding(
                    HijackKind.WritablePathEntry, directory, "machine PATH",
                    HijackExposure.Exploitable, [], directory)
                : null;
        }

        // Absent: could this user create the directory itself? CanCreate answers about a file, and
        // a directory needs the same write access in the same parent, so the parent is what to ask.
        var parent = Path.GetDirectoryName(directory.TrimEnd('\\'));
        return !string.IsNullOrEmpty(parent)
               && Directory.Exists(parent)
               && _probe.CanCreate(Path.Combine(parent, "winsight-probe.tmp"))
            ? new HijackFinding(
                HijackKind.WritablePathEntry, directory, "machine PATH (directory does not exist)",
                HijackExposure.Exploitable, [], directory)
            : null;
    }
}
