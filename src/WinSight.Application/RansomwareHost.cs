using WinSight.Ransomware;

namespace WinSight.Application;

/// <summary>
/// Assembles a ready-to-run ransomware monitor over the user's own protected directories
/// (Documents, Desktop, Pictures, Downloads, Videos and Music when available). User-mode: planting decoys and watching those folders needs no
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

    /// <summary>
    /// The monitor's real state: a directory counts as armed only when it is watched and holds its
    /// full decoy set, not merely because a directory watch is open.
    /// </summary>
    public static MonitorHealth Health(RansomwareMonitor? monitor, int requestedWhenOff) =>
        monitor is null
            ? MonitorHealth.For("Ransomware", enabled: false, armed: 0, requested: requestedWhenOff)
            : MonitorHealth.For(
                "Ransomware",
                enabled: true,
                armed: monitor.ArmedDirectoryCount,
                requested: monitor.RequestedDirectoryCount,
                lostObservations: monitor.CoverageIsIncomplete);
}
