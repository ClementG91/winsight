namespace WinSight.Response;

/// <summary>
/// The identity a response action is authorised against: a process id, the moment it started, its
/// image path and (when available) the SHA-256 of that image.
/// </summary>
/// <remarks>
/// A process id is reused the moment a process exits, so acting on a bare pid can suspend or
/// terminate an unrelated process that inherited the number. The start time makes the pair unique
/// for the machine's uptime, and the image path and hash catch the rarer case of a pid whose image
/// was replaced. Every action captures this at alert time and revalidates it immediately before
/// acting; a mismatch refuses the action rather than acting on the wrong process.
/// </remarks>
public sealed record ProcessIdentity(int Pid, long StartTimestampUtcTicks, string ImagePath, string? ImageSha256)
{
    /// <summary>
    /// Whether <paramref name="current"/> is the same running process this identity was captured for.
    /// </summary>
    /// <remarks>
    /// The pid and start time must match. The image path must match when both are known. The hash is
    /// compared only when both sides carry one, so a capture that could not afford to hash does not
    /// force a refusal, while two present-but-different hashes do.
    /// </remarks>
    public bool Matches(ProcessIdentity current)
    {
        ArgumentNullException.ThrowIfNull(current);
        if (Pid != current.Pid || StartTimestampUtcTicks != current.StartTimestampUtcTicks)
        {
            return false;
        }
        if (!string.IsNullOrEmpty(ImagePath) && !string.IsNullOrEmpty(current.ImagePath)
            && !string.Equals(ImagePath, current.ImagePath, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        return ImageSha256 is null || current.ImageSha256 is null
            || string.Equals(ImageSha256, current.ImageSha256, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>Reads live process facts, behind an interface so the decision logic is testable.</summary>
public interface IProcessInspector
{
    /// <summary>The identity of the running process with this id, or null when it is not running or
    /// cannot be read. When <paramref name="hashImage"/> is false the hash is left null.</summary>
    ProcessIdentity? Capture(int pid, bool hashImage = false);

    /// <summary>The process's image file name (no path) for the protected-process check, or null.</summary>
    string? ImageFileName(int pid);
}
