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
/// primitive. The list is matched on the image file name, case-insensitively, and is deliberately a
/// small allow-list of names rather than a heuristic, because a wrong "safe to kill" decision here is
/// unrecoverable.
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

    /// <summary>Whether a process with this id and image file name must never be acted on.</summary>
    public static bool IsProtected(int pid, string? imageFileName)
    {
        if (ReservedPids.Contains(pid))
        {
            return true;
        }
        return !string.IsNullOrWhiteSpace(imageFileName) && CriticalNames.Contains(imageFileName.Trim());
    }
}
