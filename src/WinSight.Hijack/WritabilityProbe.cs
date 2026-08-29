using System.Security.Principal;

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
}

/// <summary>Optional coverage exposed by probes that can distinguish denial from I/O failure.</summary>
public interface IWritabilityProbeCoverage
{
    int UnreadableAttempts { get; }
}

/// <summary>
/// Answers the writability question by asking the filesystem when the answer would be about an
/// unprivileged principal anyway, and by reading the directory's ACL when it would not.
/// </summary>
/// <remarks>
/// <b>Why a real attempt, in a normal session.</b> Effective access on Windows is the sum of
/// inherited allow and deny entries across every group the account belongs to, plus privileges that
/// override both. Reconstructing that from the security descriptor is where this kind of check
/// quietly gets it wrong, and a wrong answer here is a false accusation against an installed
/// program — or worse, a missed hijack reported as safe. Creating the file and immediately deleting
/// it answers the exact question being asked.
///
/// <b>Why not when elevated.</b> That method answers for <i>the current token</i>, and the interface
/// asks about an unprivileged one. Run as administrator — the mode WinSight itself recommends for
/// attribution and for scheduled tasks — the attempt succeeds in <c>C:\</c>, in
/// <c>C:\Program Files</c>, in <c>System32</c> and in every machine PATH entry. Every unquoted
/// service path graded Exploitable, every service directory writable, every PATH entry reported: a
/// tool that declares the whole machine vulnerable the moment you give it more privilege loses its
/// credibility in one run, and the measurement the design rests on ("18 PATH entries and 88
/// services, none writable") was only ever taken unelevated.
///
/// So elevation is detected, and an elevated session evaluates the DACL against the well-known
/// unprivileged principals instead — see <see cref="UnprivilegedWriteAccess"/>. Both paths refuse
/// to claim a grant they cannot prove.
///
/// <b>It never overwrites anything.</b> <see cref="FileMode.CreateNew"/> fails when the path
/// already exists, so an existing candidate is reported as not-creatable rather than being touched.
/// That is the honest answer too: if <c>C:\Program.exe</c> already exists, the interesting finding
/// is that it exists at all, which the caller reports separately.
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
    private readonly record struct DirectoryVerdict(bool CanCreate, bool Unreadable);

    /// <summary>
    /// Answers already established, keyed by directory.
    /// </summary>
    /// <remarks>
    /// <b>Why this is safe and why it matters.</b> The question is a property of the directory, not
    /// of the file name: the caller has already established that the candidate itself does not
    /// exist, and after that only the directory decides. Without the memo, one hijack scan created
    /// and deleted a real file in <c>System32</c>, in every machine PATH entry, and in each of ~88
    /// service directories - repeatedly, because a service with an unquoted path asks about several
    /// candidates in the same folder, and the PATH sweep asks about every entry again. A security
    /// tool that writes to Program Files a few hundred times per scan is doing more I/O than the
    /// scan it is performing, and every one of those writes is a chance to leave litter behind.
    ///
    /// The memo lives on the instance, which is one scan. Caching across scans would answer today's
    /// question with yesterday's ACL, which is the kind of staleness this tool exists to catch.
    /// </remarks>
    private readonly Dictionary<string, DirectoryVerdict> _byDirectory =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly Lock _gate = new();
    private readonly bool _elevated;
    private int _unreadableAttempts;

    /// <param name="elevated">
    /// Overrides the elevation detection. Tests use it to exercise both paths on one machine;
    /// production leaves it null and the current process token decides.
    /// </param>
    public WritabilityProbe(bool? elevated = null) => _elevated = elevated ?? IsProcessElevated();

    public int UnreadableAttempts => Volatile.Read(ref _unreadableAttempts);

    /// <summary>True when this probe is reading ACLs because a real attempt would answer for a
    /// privileged token. Reported so the operator knows which method produced the grading.</summary>
    public bool UsesEffectiveAccessEvaluation => _elevated;

    public bool CanCreate(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var directory = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
        {
            // No directory to plant into means nothing to plant. A missing parent is not a finding:
            // creating it would itself require write access further up, which is a different path
            // this probe will be asked about separately.
            return false;
        }

        // An existing candidate is never touched, whichever method answers: the caller reports its
        // existence separately and planting over it would destroy a real file.
        if (File.Exists(path))
        {
            return false;
        }

        return Ask(directory);
    }

    /// <summary>
    /// The directory's answer, established once and remembered. The unreadable count still rises per
    /// question rather than per directory, so the coverage figure the caller reports keeps meaning
    /// "questions I could not answer" and not "directories I could not read".
    /// </summary>
    private bool Ask(string directory)
    {
        DirectoryVerdict verdict;
        lock (_gate)
        {
            if (!_byDirectory.TryGetValue(directory, out verdict))
            {
                verdict = _elevated
                    ? new DirectoryVerdict(UnprivilegedWriteAccess.IsGrantedIn(directory), false)
                    : TryCreate(directory);
                _byDirectory[directory] = verdict;
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
        return verdict.CanCreate;
    }

    private static DirectoryVerdict TryCreate(string directory)
    {
        // A distinct name, so a real candidate is never created and never deleted by this check.
        var probe = Path.Combine(directory, $".winsight-writability-{Guid.NewGuid():N}.tmp");
        try
        {
            using (new FileStream(probe, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1,
                       FileOptions.DeleteOnClose))
            {
            }
            return new DirectoryVerdict(CanCreate: true, Unreadable: false);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            return new DirectoryVerdict(CanCreate: false, Unreadable: false);
        }
        catch (Exception ex) when (ex is IOException or NotSupportedException)
        {
            // This is not proof of non-writability (the volume may be unavailable or the path
            // syntax unsupported). Keep the conservative false answer, but expose the blind spot.
            return new DirectoryVerdict(CanCreate: false, Unreadable: true);
        }
        finally
        {
            // DeleteOnClose normally handles this; the sweep is for the case where the handle was
            // closed abnormally. A security tool must not leave litter in Program Files.
            try
            {
                if (File.Exists(probe))
                {
                    File.Delete(probe);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }
    }

    private static bool IsProcessElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or PlatformNotSupportedException)
        {
            // Unknown elevation is treated as elevated: the ACL path never claims a grant it cannot
            // prove, whereas a real attempt under an unknown token might claim one it should not.
            return true;
        }
    }
}
