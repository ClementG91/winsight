namespace WinSight.Hijack;

/// <summary>Whether an unprivileged user could place a file at a given path.</summary>
public interface IWritabilityProbe
{
    /// <summary>
    /// True when <paramref name="path"/> could be created by the current user. False when it could
    /// not, or when that cannot be determined — an unproven "yes" would be a false accusation.
    /// </summary>
    bool CanCreate(string path);
}

/// <summary>
/// Answers the writability question by asking the filesystem, not by reasoning about ACLs.
/// </summary>
/// <remarks>
/// <b>Why a real attempt rather than reading the DACL.</b> Effective access on Windows is the sum of
/// inherited allow and deny entries across every group the account belongs to, plus privileges that
/// override both. Reconstructing that from the security descriptor is where this kind of check
/// quietly gets it wrong, and a wrong answer here is a false accusation against an installed
/// program — or worse, a missed hijack reported as safe. Creating the file and immediately deleting
/// it answers the exact question being asked.
///
/// <b>It never overwrites anything.</b> <see cref="FileMode.CreateNew"/> fails when the path
/// already exists, so an existing candidate is reported as not-creatable rather than being touched.
/// That is the honest answer too: if <c>C:\Program.exe</c> already exists, the interesting finding
/// is that it exists at all, which the caller reports separately.
/// </remarks>
public sealed class WritabilityProbe : IWritabilityProbe
{
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
                                     or IOException
                                     or NotSupportedException
                                     or System.Security.SecurityException)
        {
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
}
