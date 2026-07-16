namespace WinSight.NetMonitor;

/// <summary>
/// Recovers a process's executable path from the command line the kernel reports at process start.
/// </summary>
/// <remarks>
/// The kernel's process events carry the command line and a short image name, but no full path
/// field, so the path has to be read out of the command line. That is where the classic ambiguity
/// lives: <c>C:\Program Files\My App\app.exe --flag</c> is unquoted and splitting on the first
/// space yields <c>C:\Program</c>. The short image name resolves it — it says where the executable
/// ends, whatever the spaces before it.
/// </remarks>
public static class ProcessCommandLine
{
    /// <summary>
    /// The executable path in <paramref name="commandLine"/>, or null when no absolute path can be
    /// read out of it. Null is the honest answer: a policy keyed on a guess is worse than none.
    /// </summary>
    /// <param name="commandLine">The full command line, as the kernel reported it.</param>
    /// <param name="imageFileName">The short image name (<c>app.exe</c>), used to find the end of
    /// an unquoted path that contains spaces.</param>
    public static string? ExtractExecutablePath(string? commandLine, string? imageFileName)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return null;
        }
        var line = commandLine.TrimStart();

        // A quoted path is unambiguous, and is what Windows produces for most launches.
        if (line.StartsWith('"'))
        {
            var close = line.IndexOf('"', 1);
            return close > 1 ? Qualify(line[1..close]) : null;
        }

        // Unquoted: the image name says where the executable ends, so a path with spaces survives.
        if (!string.IsNullOrWhiteSpace(imageFileName))
        {
            var at = line.IndexOf(imageFileName, StringComparison.OrdinalIgnoreCase);
            if (at >= 0)
            {
                return Qualify(line[..(at + imageFileName.Length)]);
            }
        }

        // No image name to anchor on: the first token is the best available reading, and it is
        // correct whenever the path has no spaces.
        var space = line.IndexOf(' ');
        return Qualify(space < 0 ? line : line[..space]);
    }

    private static string? Qualify(string candidate)
    {
        var path = candidate.Trim().Trim('"');
        if (path.Length == 0)
        {
            return null;
        }
        try
        {
            return Path.IsPathFullyQualified(path) ? Path.GetFullPath(path) : null;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }
}

/// <summary>
/// Maps a live process id to its executable, kept current by the kernel's own process events.
/// </summary>
/// <remarks>
/// This exists because a connection cannot be attributed after the fact. An earlier version asked
/// the operating system about the process when the connection event arrived, and it never worked:
/// ETW delivers a second or more late, and the processes that matter most — a quick reach-out that
/// exits immediately — are already gone by then. Every short-lived connection went unattributed,
/// silently, while the unit tests passed.
///
/// Recording the path when the kernel says the process started removes the race entirely: the
/// answer is captured while the process is alive and is still there when the connection arrives.
///
/// Process ids are reused, which is why an entry is replaced on start rather than merged: the
/// kernel's ordered stream means a reused id has been re-announced before any connection can be
/// attributed to its new owner. Entries for dead processes are kept briefly on purpose — a
/// connection can be delivered just after the process ended, and dropping the path immediately
/// would lose exactly the event worth reporting.
/// </remarks>
public sealed class ProcessPathIndex
{
    /// <summary>How long a dead process's path stays resolvable, covering ETW delivery lag.</summary>
    public static readonly TimeSpan DeadRetention = TimeSpan.FromSeconds(30);

    /// <summary>A ceiling on tracked processes, so a fork bomb cannot grow this without bound.</summary>
    public const int MaxTracked = 8192;

    private readonly Dictionary<int, Entry> _byPid = [];
    private readonly Lock _gate = new();

    private sealed record Entry(string Path, DateTimeOffset? DiedUtc);

    public int Count
    {
        get { lock (_gate) { return _byPid.Count; } }
    }

    /// <summary>Records a process's executable. Replaces any earlier entry for the same id.</summary>
    public void Started(int processId, string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        lock (_gate)
        {
            // Refusing to grow past the ceiling would blind us to every new process; dropping the
            // longest-dead entries keeps the live ones, which are the ones connections need.
            if (_byPid.Count >= MaxTracked && !_byPid.ContainsKey(processId))
            {
                DropOldestDead();
            }
            if (_byPid.Count < MaxTracked || _byPid.ContainsKey(processId))
            {
                _byPid[processId] = new Entry(executablePath, DiedUtc: null);
            }
        }
    }

    /// <summary>
    /// Marks a process as gone. The path stays resolvable for <see cref="DeadRetention"/> so a
    /// connection delivered just after the process ended can still be attributed.
    /// </summary>
    public void Stopped(int processId, DateTimeOffset whenUtc)
    {
        lock (_gate)
        {
            if (_byPid.TryGetValue(processId, out var entry) && entry.DiedUtc is null)
            {
                _byPid[processId] = entry with { DiedUtc = whenUtc };
            }
        }
    }

    /// <summary>The executable of <paramref name="processId"/>, or null when it is not known.</summary>
    public string? Resolve(int processId)
    {
        lock (_gate)
        {
            return _byPid.TryGetValue(processId, out var entry) ? entry.Path : null;
        }
    }

    /// <summary>Forgets processes that have been dead longer than <see cref="DeadRetention"/>.</summary>
    public void Prune(DateTimeOffset nowUtc)
    {
        lock (_gate)
        {
            foreach (var pid in _byPid
                .Where(pair => pair.Value.DiedUtc is { } died && nowUtc - died > DeadRetention)
                .Select(pair => pair.Key)
                .ToArray())
            {
                _byPid.Remove(pid);
            }
        }
    }

    private void DropOldestDead()
    {
        var oldest = _byPid
            .Where(pair => pair.Value.DiedUtc is not null)
            .OrderBy(pair => pair.Value.DiedUtc)
            .Select(pair => pair.Key)
            .FirstOrDefault(-1);
        if (oldest >= 0)
        {
            _byPid.Remove(oldest);
        }
    }
}
