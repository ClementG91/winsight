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

        return _elevated ? UnprivilegedWriteAccess.IsGrantedIn(directory) : TryCreate(directory);
    }

    private bool TryCreate(string directory)
    {
        // A distinct name, so a real candidate is never created and never deleted by this check.
        var probe = Path.Combine(directory, $".winsight-writability-{Guid.NewGuid():N}.tmp");
        try
        {
            using (new FileStream(probe, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1,
                       FileOptions.DeleteOnClose))
            {
            }
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            return false;
        }
        catch (Exception ex) when (ex is IOException or NotSupportedException)
        {
            // This is not proof of non-writability (the volume may be unavailable or the path
            // syntax unsupported). Keep the conservative false answer, but expose the blind spot.
            Interlocked.Increment(ref _unreadableAttempts);
            return false;
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
