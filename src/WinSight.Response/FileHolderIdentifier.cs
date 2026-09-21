namespace WinSight.Response;

/// <summary>How sure the identifier is that it named the right actionable process.</summary>
public enum IdentificationConfidence
{
    /// <summary>No unelevated holder could be named; elevated attribution may still apply.</summary>
    None,

    /// <summary>Exactly one non-protected process holds the files; safe to offer an action against it.</summary>
    High,

    /// <summary>Several non-protected processes hold the files; the operator must pick, none is auto-actioned.</summary>
    Ambiguous,
}

/// <summary>A process named as holding the queried files, captured as an actionable identity.</summary>
public sealed record FileHolderCandidate(ProcessIdentity Identity, string AppName);

/// <summary>The outcome of trying to name the processes holding a set of files.</summary>
public sealed record FileHolderIdentification(
    IReadOnlyList<FileHolderCandidate> Candidates,
    IdentificationConfidence Confidence,
    string Reason);

/// <summary>
/// Turns "these files were just touched" into "this is the process, captured as an identity we can
/// safely act on": ask the OS who holds the files, revalidate each named pid against a fresh capture
/// (so a pid recycled between the two queries is dropped), and refuse protected/critical processes.
/// </summary>
/// <remarks>
/// This is the unelevated identification path RansomWhere? parity needs: on a decoy touch, name the
/// encrypting process without a driver and without elevation. It never acts; it only produces
/// candidates and a confidence for the operator (or the opt-in suspension gate) to use.
/// </remarks>
public sealed class FileHolderIdentifier
{
    private readonly IFileLockInspector _locks;
    private readonly IProcessInspector _inspector;

    public FileHolderIdentifier(IFileLockInspector locks, IProcessInspector inspector)
    {
        _locks = locks ?? throw new ArgumentNullException(nameof(locks));
        _inspector = inspector ?? throw new ArgumentNullException(nameof(inspector));
    }

    /// <summary>Names the non-protected processes holding <paramref name="touchedFiles"/> right now.</summary>
    public FileHolderIdentification Identify(IReadOnlyCollection<string> touchedFiles)
    {
        ArgumentNullException.ThrowIfNull(touchedFiles);
        var holders = _locks.ProcessesHolding(touchedFiles);
        var candidates = new List<FileHolderCandidate>();
        var refusedProtected = false;

        foreach (var holder in holders)
        {
            var identity = _inspector.Capture(holder.Pid, hashImage: true);
            if (identity is null || identity.StartTimestampUtcTicks != holder.StartTimestampUtcTicks)
            {
                // Not running any more, unreadable, or the pid was recycled since the RM query: not
                // something we can safely act on.
                continue;
            }
            if (ProtectedProcesses.IsProtected(identity))
            {
                refusedProtected = true;
                continue;
            }
            var appName = string.IsNullOrEmpty(holder.AppName)
                ? Path.GetFileName(identity.ImagePath)
                : holder.AppName;
            candidates.Add(new FileHolderCandidate(identity, appName));
        }

        return candidates.Count switch
        {
            0 => new FileHolderIdentification(candidates, IdentificationConfidence.None,
                refusedProtected
                    ? "only protected processes hold the files; refused"
                    : "no unelevated holder found; elevated attribution may still apply"),
            1 => new FileHolderIdentification(candidates, IdentificationConfidence.High,
                "one non-protected process holds the touched files"),
            _ => new FileHolderIdentification(candidates, IdentificationConfidence.Ambiguous,
                $"{candidates.Count} non-protected processes hold the touched files"),
        };
    }
}
