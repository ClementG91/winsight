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
    PrintMonitor,
    NetshHelper,
    ComHijack,
    AppCertDll,
    TimeProvider,
    Screensaver,
    SilentProcessExit,
    CredentialProvider,
    BrowserHelperObject,
    WindowsLoadRun,
    PrintProvider,
    // Phase 1.2+: Winsock LSP, shell extensions, ...
    // Note: installed shim databases (.sdb) are intentionally NOT enumerated here: a .sdb is
    // never Authenticode-signed, so the signature model would flag every legitimate shim as
    // "unsigned/suspicious" (a guaranteed false positive). Revisit only with an info-only,
    // non-signature presentation.
}

/// <summary>A user-facing persistence inspection result, distinct from severity.</summary>
public enum PersistenceStatus
{
    FileMissing,
    SignatureValid,
    Unsigned,
    InvalidSignature,
    AccessDenied,
    VerificationError,
}

/// <summary>
/// One persistently-installed item, the unit KnockKnock-style scanning reveals.
/// It records WHERE it persists (Vector/Location), the raw command, the resolved
/// executable, and that executable's signature verdict. Recognition/inspection only;
/// WinSight never silently removes anything.
/// </summary>
/// <param name="Vector">Which autostart surface it was found in.</param>
/// <param name="Name">The entry's name (registry value name, service name, ...).</param>
/// <param name="Location">Human-readable source location (e.g. the registry path).</param>
/// <param name="Command">The raw command/value as stored.</param>
/// <param name="ImagePath">The resolved on-disk executable, or null if not resolvable.</param>
/// <param name="ExpectedImagePath">Normalized target Windows would load, even when absent.</param>
/// <param name="ImageStatus">Whether that target is present, absent, inaccessible or unresolved.</param>
/// <param name="Signature">The executable's Authenticode verdict.</param>
public sealed record AutostartEntry(
    AutostartVector Vector,
    string Name,
    string Location,
    string Command,
    string? ImagePath,
    string? ExpectedImagePath,
    ImageResolutionStatus ImageStatus,
    SignatureVerdict Signature)
{
    public PersistenceStatus Status => ImageStatus switch
    {
        ImageResolutionStatus.FileMissing => PersistenceStatus.FileMissing,
        ImageResolutionStatus.AccessDenied => PersistenceStatus.AccessDenied,
        ImageResolutionStatus.Error => PersistenceStatus.VerificationError,
        ImageResolutionStatus.Unresolved => PersistenceStatus.VerificationError,
        _ => Signature.State switch
        {
            SignatureState.SignedTrusted => PersistenceStatus.SignatureValid,
            SignatureState.Unsigned => PersistenceStatus.Unsigned,
            SignatureState.SignedUntrusted => PersistenceStatus.InvalidSignature,
            _ => PersistenceStatus.VerificationError,
        },
    };

    /// <summary>
    /// True when the item is worth a second look: no resolvable image, or an image
    /// that is unsigned / signed-but-untrusted. This is a triage hint, not a verdict.
    /// </summary>
    public bool IsSuspicious =>
        Status is PersistenceStatus.FileMissing
            or PersistenceStatus.Unsigned
            or PersistenceStatus.InvalidSignature
            or PersistenceStatus.AccessDenied;
}
