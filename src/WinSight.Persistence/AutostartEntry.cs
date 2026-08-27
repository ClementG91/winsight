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
    /// Why this entry's <b>command line</b> is worth a second look, independently of its file.
    /// </summary>
    /// <remarks>
    /// Kept separate from <see cref="Status"/> because the two answer different questions and the
    /// interesting case is precisely where they disagree: a Windows-signed interpreter handed
    /// somebody else's payload is <see cref="PersistenceStatus.SignatureValid"/> and still worth
    /// investigating. See <see cref="InterpreterAbuseTriage"/>.
    /// </remarks>
    public InterpreterAbuse Abuse => InterpreterAbuseTriage.Classify(this);

    /// <summary>
    /// True when the item is worth a second look: no resolvable image, an image that is
    /// unsigned / signed-but-untrusted, or a command line handing a signed interpreter a payload
    /// its signature does not cover. This is a triage hint, not a verdict.
    /// </summary>
    /// <remarks>
    /// <b><see cref="ImageResolutionStatus.Unresolved"/> is tested directly, not through
    /// <see cref="Status"/>.</b> Both an unresolvable command and a transient I/O failure while
    /// probing collapse into <see cref="PersistenceStatus.VerificationError"/>, and only the first
    /// is a finding: "this autostart entry names something Windows can locate and WinSight cannot"
    /// is a real gap in the file-based verdict, whereas a sharing violation on one probe is a
    /// coverage problem the report accounts for separately. Reading the coarse status here would
    /// have conflated them, so the condition this documentation had always claimed was never
    /// actually implemented.
    ///
    /// <b>What it costs.</b> Measured on the development desktop after the resolution fix:
    /// 1 entry out of 4 350 (an <c>ActiveSetup</c> StubPath whose whole value is the single
    /// character <c>U</c>). An unresolvable autostart command is rare, and each one is exactly the
    /// case where no signature verdict exists to speak for the entry.
    /// </remarks>
    public bool IsSuspicious =>
        Status is PersistenceStatus.FileMissing
            or PersistenceStatus.Unsigned
            or PersistenceStatus.InvalidSignature
            or PersistenceStatus.AccessDenied
        || ImageStatus is ImageResolutionStatus.Unresolved
        // "Signed and trusted" is worth no more than the root it chains to, and WinVerifyTrust
        // consults CurrentUser\Root - a store any account writes with no elevation. An implant
        // signed beneath a root imported that way read SignatureValid here, which defeated the
        // central claim of the whole scanner for the price of one unprivileged store write.
        || Signature.RestsOnUserInstalledTrust
        || Abuse != InterpreterAbuse.None;
}
