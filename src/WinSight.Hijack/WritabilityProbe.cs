using WinSight.Core;

namespace WinSight.Hijack;

/// <summary>Whether an unprivileged user could place a file at a given path.</summary>
public interface IWritabilityProbe
{
    /// <summary>
    /// True when <paramref name="path"/> could be created by an unprivileged principal. False when
    /// it could not, or when that cannot be determined — an unproven "yes" would be a false
    /// accusation.
    /// </summary>
    bool CanCreate(string path);

    /// <summary>
    /// True when the directory <paramref name="path"/>, which does not exist, could be created by an
    /// unprivileged principal in its (existing) parent. False when it could not or when that cannot
    /// be determined.
    /// </summary>
    /// <remarks>
    /// Not the same question as <see cref="CanCreate"/> asked about a file in the same parent:
    /// Windows grants creating a subdirectory and creating a file separately, and the system drive
    /// root grants a standard user the first without the second. The default answer defers to
    /// <see cref="CanCreate"/> for probes that cannot tell the two apart.
    /// </remarks>
    bool CanCreateDirectory(string path) => CanCreate(path);
}

/// <summary>Optional coverage exposed by probes that can distinguish denial from I/O failure.</summary>
public interface IWritabilityProbeCoverage
{
    int UnreadableAttempts { get; }

    /// <summary>
    /// True when at least one answer came from the well-known-group DACL model rather than from
    /// <c>AccessCheck</c> with a non-elevated token (see <see cref="WriteAccessEvaluation"/>).
    /// </summary>
    bool UsedWellKnownPrincipals => false;
}

/// <summary>
/// Answers the writability question by asking Windows, through <see cref="UnprivilegedWriteAccess"/>,
/// whether the current user without elevation could create the object - without creating anything.
/// </summary>
/// <remarks>
/// <b>It writes nothing.</b> It used to answer by creating and deleting a probe file in every
/// directory it graded - <c>C:\</c>, <c>Program Files</c>, each auto-start service's directory and
/// each machine PATH entry - and answered for the current token, so an elevated run needed a second,
/// different method. <c>AccessCheck</c> over the directory's security descriptor with the
/// non-elevated token asks the same question of the same evaluator Windows uses, from both sessions,
/// and leaves no trace for endpoint protection to notice.
///
/// <b>It never reports an existing object as plantable.</b> If <c>C:\Program.exe</c> already exists,
/// the interesting finding is that it exists at all, which the caller reports separately.
/// </remarks>
public sealed class WritabilityProbe : IWritabilityProbe, IWritabilityProbeCoverage
{
    /// <summary>
    /// The answer for one directory, remembered for the lifetime of this probe.
    /// </summary>
    /// <param name="CanCreate">Whether an unprivileged principal could place a file there.</param>
    /// <param name="Unreadable">
    /// Whether the attempt failed for a reason that is not proof either way, so the caller's
    /// coverage count still rises on every question asked about this directory.
    /// </param>
    private readonly record struct DirectoryVerdict(
        bool CanCreate, bool Unreadable, WriteAccessEvaluation Evaluation);

    /// <summary>
    /// Answers already established, keyed by directory.
    /// </summary>
    /// <remarks>
    /// <b>Why this is safe and why it matters.</b> The question is a property of the directory, not
    /// of the file name: the caller has already established that the candidate itself does not
    /// exist, and after that only the directory decides. A service with an unquoted path asks about
    /// several candidates in the same folder, the PATH sweep asks about every entry again, and the
    /// phantom-import check asks about each directory of ~90 search orders; without the memo each of
    /// those questions reread the descriptor and reran the access check.
    ///
    /// The memo lives on the instance, which is one scan. Caching across scans would answer today's
    /// question with yesterday's ACL, which is the kind of staleness this tool exists to catch.
    /// </remarks>
    private readonly Dictionary<string, DirectoryVerdict> _byDirectory =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The same memo for "could a subdirectory be created here", a separate right.</summary>
    private readonly Dictionary<string, DirectoryVerdict> _subdirectoryByDirectory =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly Lock _gate = new();
    private int _unreadableAttempts;
    private int _wellKnownPrincipalAnswers;

    /// <param name="elevated">
    /// Kept for source compatibility and ignored: both sessions now ask Windows the same question
    /// with the non-elevated token, so there is no longer a per-elevation method to select.
    /// </param>
    public WritabilityProbe(bool? elevated = null) => _ = elevated;

    public int UnreadableAttempts => Volatile.Read(ref _unreadableAttempts);

    /// <inheritdoc />
    public bool UsedWellKnownPrincipals => Volatile.Read(ref _wellKnownPrincipalAnswers) > 0;

    /// <summary>True while every answer so far came from <c>AccessCheck</c> with a non-elevated
    /// token. Reported so the operator knows which method produced the grading.</summary>
    public bool UsesEffectiveAccessEvaluation => !UsedWellKnownPrincipals;

    public bool CanCreate(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var directory = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(directory)
            || !AutomaticFileAccess.DirectoryExists(directory))
        {
            // No directory to plant into means nothing to plant. A missing parent is not a finding:
            // creating it would itself require write access further up, which is a different path
            // this probe will be asked about separately.
            return false;
        }

        // An existing candidate is never touched, whichever method answers: the caller reports its
        // existence separately and planting over it would destroy a real file.
        if (AutomaticFileAccess.FileExists(path)
            || AutomaticFileAccess.DirectoryExists(path)
            || !AutomaticFileAccess.IsLocal(path))
        {
            return false;
        }

        return Ask(directory, PlantedObject.File);
    }

    public bool CanCreateDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var parent = Path.GetDirectoryName(path.TrimEnd('\\', '/'));
        if (string.IsNullOrEmpty(parent)
            || !AutomaticFileAccess.DirectoryExists(parent))
        {
            return false;
        }

        // Something already there - a directory or a file of that name - is never touched, and is
        // not something anybody can create.
        if (AutomaticFileAccess.DirectoryExists(path)
            || AutomaticFileAccess.FileExists(path)
            || !AutomaticFileAccess.IsLocal(path))
        {
            return false;
        }

        return Ask(parent, PlantedObject.Directory);
    }

    /// <summary>
    /// The directory's answer, established once and remembered. The unreadable count still rises per
    /// question rather than per directory, so the coverage figure the caller reports keeps meaning
    /// "questions I could not answer" and not "directories I could not read".
    /// </summary>
    private bool Ask(string directory, PlantedObject planted)
    {
        var memo = planted == PlantedObject.Directory ? _subdirectoryByDirectory : _byDirectory;
        DirectoryVerdict verdict;
        lock (_gate)
        {
            if (!memo.TryGetValue(directory, out verdict))
            {
                var readable = UnprivilegedWriteAccess.TryIsGrantedIn(
                    directory,
                    planted,
                    out var granted,
                    out var evaluation);
                verdict = new DirectoryVerdict(granted, Unreadable: !readable, evaluation);
                memo[directory] = verdict;
                return Report(verdict);
            }
        }
        return Report(verdict);
    }

    private bool Report(DirectoryVerdict verdict)
    {
        if (verdict.Unreadable)
        {
            Interlocked.Increment(ref _unreadableAttempts);
        }
        else if (verdict.Evaluation == WriteAccessEvaluation.WellKnownPrincipals)
        {
            Interlocked.Increment(ref _wellKnownPrincipalAnswers);
        }
        return verdict.CanCreate;
    }

}
