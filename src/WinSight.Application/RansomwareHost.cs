using WinSight.Ransomware;

namespace WinSight.Application;

/// <summary>
/// Assembles a ready-to-run ransomware monitor over the user's own protected directories
/// (Documents, Desktop, Pictures). User-mode: planting decoys and watching those folders needs no
/// elevation. One call the dashboard hosts while it is running.
/// </summary>
public static class RansomwareHost
{
    /// <summary>
    /// Builds a monitor over the default protected directories. It does no work until
    /// <see cref="RansomwareMonitor.Start"/> is called, which sweeps orphaned decoys from a previous
    /// run, plants fresh ones, and begins watching. Disposing removes the decoys again.
    /// </summary>
    public static RansomwareMonitor CreateDefault() => new();
}
