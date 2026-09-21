namespace WinSight.Response;

/// <summary>
/// The processes a response action must never suspend or terminate, regardless of what an alert
/// claims about them.
/// </summary>
/// <remarks>
/// Suspending or killing a core Windows process (the session manager, the client/server subsystem,
/// the local security authority, the service host that owns half the machine) does not stop a
/// threat — it bugchecks or hangs the machine, which is a worse outcome than the threat. WinSight's
/// own processes are refused too: a tool that can be tricked into killing itself is a denial-of-service
/// primitive. A basename alone is never identity: malware can call itself lsass.exe or winsight.exe.
/// Windows names are therefore protected only under the real System32/SysWOW64 directories, and
/// WinSight sibling names only beside the currently running component. An identity with no verified
/// image path fails closed because acting on an unknown process is not recoverable.
/// </remarks>
public static class ProtectedProcesses
{
    private static readonly HashSet<string> CriticalNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "registry", "memory compression", "smss.exe", "csrss.exe", "wininit.exe",
        "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "fontdrvhost.exe", "dwm.exe",
        "svchost.exe", "sihost.exe", "ntoskrnl.exe", "system idle process",
        // WinSight's own surface: the dashboard, CLI, MCP server and the privileged service.
        "winsight.exe", "winsight-dashboard.exe", "winsight-firewall-service.exe",
    };

    /// <summary>The pid values Windows reserves and that never name a killable process.</summary>
    private static readonly HashSet<int> ReservedPids = [0, 4];

    /// <summary>PID-only identities that never require an image-path read.</summary>
    public static bool IsAlwaysProtected(int pid) =>
        ReservedPids.Contains(pid) || pid == Environment.ProcessId;

    /// <summary>Whether this captured process identity must never be acted on.</summary>
    public static bool IsProtected(ProcessIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return IsProtected(
            identity,
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            [AppContext.BaseDirectory],
            Environment.ProcessId);
    }

    internal static bool IsProtected(
        ProcessIdentity identity,
        string windowsDirectory,
        IReadOnlyCollection<string> productDirectories,
        int currentProcessId)
    {
        if (ReservedPids.Contains(identity.Pid) || identity.Pid == currentProcessId)
        {
            return true;
        }
        if (!TryCanonicalize(identity.ImagePath, out var imagePath))
        {
            return true;
        }
        var name = Path.GetFileName(imagePath);
        if (!CriticalNames.Contains(name))
        {
            return false;
        }
        if (name.StartsWith("winsight", StringComparison.OrdinalIgnoreCase))
        {
            return productDirectories.Any(directory => IsDirectChild(imagePath, directory));
        }
        return IsDirectChild(imagePath, Path.Combine(windowsDirectory, "System32"))
            || IsDirectChild(imagePath, Path.Combine(windowsDirectory, "SysWOW64"));
    }

    private static bool IsDirectChild(string path, string directory) =>
        TryCanonicalize(directory, out var canonicalDirectory)
        && string.Equals(
            Path.GetDirectoryName(path)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            canonicalDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            StringComparison.OrdinalIgnoreCase);

    private static bool TryCanonicalize(string? path, out string canonical)
    {
        canonical = string.Empty;
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }
        try
        {
            if (!Path.IsPathFullyQualified(path))
            {
                return false;
            }
            canonical = Path.GetFullPath(path);
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }
}
