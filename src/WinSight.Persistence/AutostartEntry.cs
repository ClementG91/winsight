using WinSight.Core;

namespace WinSight.Persistence;

/// <summary>The class of autostart vector an entry was found in.</summary>
public enum AutostartVector
{
    RunKey,
    Service,
    Winlogon,
    ScheduledTask,
    AppInitDll,
    ImageHijack,
    ActiveSetup,
    BootExecute,
    WmiSubscription,
    StartupFolder,
    LsaPackage,
    // Phase 1.2+: print monitors, netsh helpers, COM hijacks, ...
}

/// <summary>
/// One persistently-installed item — the unit KnockKnock-style scanning reveals.
/// It records WHERE it persists (Vector/Location), the raw command, the resolved
/// executable, and that executable's signature verdict. Recognition/inspection only;
/// WinSight never silently removes anything.
/// </summary>
/// <param name="Vector">Which autostart surface it was found in.</param>
/// <param name="Name">The entry's name (registry value name, service name, ...).</param>
/// <param name="Location">Human-readable source location (e.g. the registry path).</param>
/// <param name="Command">The raw command/value as stored.</param>
/// <param name="ImagePath">The resolved on-disk executable, or null if not resolvable.</param>
/// <param name="Signature">The executable's Authenticode verdict.</param>
public sealed record AutostartEntry(
    AutostartVector Vector,
    string Name,
    string Location,
    string Command,
    string? ImagePath,
    SignatureVerdict Signature)
{
    /// <summary>
    /// True when the item is worth a second look: no resolvable image, or an image
    /// that is unsigned / signed-but-untrusted. This is a triage hint, not a verdict.
    /// </summary>
    public bool IsSuspicious =>
        ImagePath is null ||
        Signature.State is SignatureState.Unsigned
            or SignatureState.SignedUntrusted
            or SignatureState.Missing;
}
