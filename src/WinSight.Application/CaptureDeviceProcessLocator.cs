using WinSight.AvMonitor;
using WinSight.Response;

namespace WinSight.Application;

/// <summary>A running process matched to a capture-device user, captured as an actionable identity.</summary>
public sealed record CaptureDeviceProcess(ProcessIdentity Identity, string ImagePath);

/// <summary>How confidently a device user was mapped to a process.</summary>
public enum DeviceProcessResolution
{
    /// <summary>Exactly one running process matches; it can be offered for a Block (terminate) decision.</summary>
    Resolved,

    /// <summary>Several processes share the image; the operator picks, none is auto-actioned.</summary>
    Ambiguous,

    /// <summary>The app that used the device is no longer running.</summary>
    NotRunning,

    /// <summary>The app is a packaged app; process mapping by package family is not implemented yet.</summary>
    Unsupported,
}

/// <summary>The processes (if any) behind a device usage, and how sure the mapping is.</summary>
public sealed record CaptureDeviceProcessMatch(
    DeviceProcessResolution Resolution,
    IReadOnlyList<CaptureDeviceProcess> Processes,
    string Reason);

/// <summary>Enumerates the running processes as (pid, image path), behind an interface for testing.</summary>
public interface IRunningImageSource
{
    IReadOnlyList<RunningImage> All();
}

/// <summary>One running process reduced to what device-user matching needs.</summary>
public sealed record RunningImage(int Pid, string ImagePath);

/// <summary>
/// Turns "this application used the webcam/microphone" into "these are the processes it is running
/// as, captured as identities we can act on". This is the OverSight-parity step from naming an
/// application to naming a process, so a Block can terminate the right process through the response
/// layer (with the usual revalidation and protected-process refusal).
/// </summary>
/// <remarks>
/// Desktop (non-packaged) apps are matched by image path, the identity the consent store records.
/// Packaged apps are reported as unsupported rather than guessed, because mapping a package id to its
/// processes needs package-family resolution that is not built yet; naming the wrong process would be
/// worse than naming none.
/// </remarks>
public sealed class CaptureDeviceProcessLocator
{
    private readonly IRunningImageSource _processes;
    private readonly IProcessInspector _inspector;

    public CaptureDeviceProcessLocator(IRunningImageSource processes, IProcessInspector inspector)
    {
        _processes = processes ?? throw new ArgumentNullException(nameof(processes));
        _inspector = inspector ?? throw new ArgumentNullException(nameof(inspector));
    }

    /// <summary>Finds the running processes behind <paramref name="usage"/>.</summary>
    public CaptureDeviceProcessMatch Locate(DeviceUsage usage)
    {
        ArgumentNullException.ThrowIfNull(usage);
        if (usage.Packaged)
        {
            return new CaptureDeviceProcessMatch(DeviceProcessResolution.Unsupported, [],
                "packaged app; process mapping by package family is not implemented");
        }
        if (string.IsNullOrWhiteSpace(usage.App))
        {
            return new CaptureDeviceProcessMatch(DeviceProcessResolution.NotRunning, [], "no image path recorded");
        }

        var matched = new List<CaptureDeviceProcess>();
        foreach (var candidate in _processes.All())
        {
            if (!string.Equals(candidate.ImagePath, usage.App, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            var identity = _inspector.Capture(candidate.Pid, hashImage: true);
            if (identity is not null)
            {
                matched.Add(new CaptureDeviceProcess(identity, candidate.ImagePath));
            }
        }

        return matched.Count switch
        {
            0 => new CaptureDeviceProcessMatch(DeviceProcessResolution.NotRunning, matched,
                "the application that used the device is no longer running"),
            1 => new CaptureDeviceProcessMatch(DeviceProcessResolution.Resolved, matched,
                "one running process matches the device user"),
            _ => new CaptureDeviceProcessMatch(DeviceProcessResolution.Ambiguous, matched,
                $"{matched.Count} running processes share this image"),
        };
    }
}
