namespace WinSight.Hijack;

/// <summary>How exposed an unquoted service path actually is.</summary>
public enum HijackExposure
{
    /// <summary>Unquoted, but no earlier candidate can be created by this user.</summary>
    Latent,

    /// <summary>An earlier candidate can be created by this user: the service is hijackable now.</summary>
    Exploitable,

    /// <summary>
    /// An earlier candidate already exists on disk. Either the machine is already hijacked, or a
    /// legitimate program happens to sit there — both are worth a human look immediately.
    /// </summary>
    Occupied,
}

/// <summary>A service whose registered command line can be pre-empted, and by what.</summary>
/// <param name="Service">The service name.</param>
/// <param name="CommandLine">Its registered command line, as the registry holds it.</param>
/// <param name="Exposure">How exposed it is in practice.</param>
/// <param name="Candidates">Every path Windows would try first, in order.</param>
/// <param name="ActionablePath">
/// The specific path that makes this exploitable or occupied — the one to go and look at. Null when
/// the finding is latent.
/// </param>
public sealed record HijackFinding(
    string Service,
    string CommandLine,
    HijackExposure Exposure,
    IReadOnlyList<string> Candidates,
    string? ActionablePath);

/// <summary>
/// Turns unquoted service paths into findings ranked by whether they can actually be exploited.
/// </summary>
/// <remarks>
/// <b>Why exposure is graded rather than everything being flagged.</b> Unquoted service paths are
/// common on Windows — plenty of vendors ship them — and almost all of them sit under
/// <c>C:\Program Files</c>, where an unprivileged user cannot create the earlier candidate. Flagging
/// all of them equally produces a wall of items nobody reads, and the two that matter are lost in
/// it. The grade is decided by asking the filesystem, not by pattern-matching the path: whether a
/// directory is writable is a fact about this machine, and a machine with loosened permissions on
/// <c>C:\</c> is exactly the one that needs telling.
/// </remarks>
public sealed class HijackTriage(IWritabilityProbe? probe = null)
{
    private readonly IWritabilityProbe _probe = probe ?? new WritabilityProbe();

    /// <summary>The finding for one service, or null when its command line is not hijackable.</summary>
    public HijackFinding? Assess(string service, string? commandLine)
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
                    service, commandLine!, HijackExposure.Occupied, candidates, candidate);
            }
        }

        foreach (var candidate in candidates)
        {
            if (_probe.CanCreate(candidate))
            {
                return new HijackFinding(
                    service, commandLine!, HijackExposure.Exploitable, candidates, candidate);
            }
        }

        return new HijackFinding(
            service, commandLine!, HijackExposure.Latent, candidates, ActionablePath: null);
    }
}
