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
    RunOnceEx,
    SecurityProvider,
    JustInTimeDebugger,
    PowerShellProfile,
    ProfilerInjection,
    // Still not enumerated, named here rather than left implicit: Winsock LSP catalog entries
    // (their DLL path lives inside a packed binary blob), shell extension handlers,
    // Winlogon\Notify (which modern Windows no longer executes), Group Policy scripts and Office
    // add-ins.
    //
    // BITS transfer jobs (T1197) are a real surface and are deliberately declared here rather than
    // half-implemented. A job's notify command line is reachable only through the
    // IBackgroundCopyManager COM interfaces, enumerating other users' jobs requires elevation, and
    // neither the interop nor the elevated path can be exercised on a development machine without
    // creating BITS jobs on it. Shipping untested COM interop that reaches a privileged enumeration
    // is worse than saying it is not covered - and saying so is what lets somebody decide whether
    // they need it.
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
/// <param name="OriginalFileName">
/// The name the vendor compiled into the image (VS_VERSIONINFO), when it could be read.
/// </param>
/// <remarks>
/// <b>Why the original file name is carried.</b> The command-line triage matches the resolved file
/// name against a table of interpreters, so copying <c>powershell.exe</c> to <c>updater.exe</c>
/// (MITRE T1036.003, masquerading) took the entry out of the table entirely and the rule never
/// fired. The name a vendor compiles into the image survives a copy, and it is read once during the
/// scan - beside the signature check, which is already doing I/O - so
/// <see cref="IsSuspicious"/> stays a pure function that cannot block or throw into a scan.
/// </remarks>
public sealed record AutostartEntry(
    AutostartVector Vector,
    string Name,
    string Location,
    string Command,
    string? ImagePath,
    string? ExpectedImagePath,
    ImageResolutionStatus ImageStatus,
    SignatureVerdict Signature,
    string? OriginalFileName = null)
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
    public bool IsSuspicious => IsUnverified || IsAdverse;

    /// <summary>
    /// True when the entry's check could not complete: the target is not on disk, could not be
    /// opened, or the command names nothing resolvable. Nothing is known about it either way.
    /// </summary>
    /// <remarks>
    /// <b>Split out because these are not findings.</b> They were reported at the same weight as an
    /// unsigned DLL in an IFEO Debugger value, and an orphaned registration left by an OEM
    /// uninstaller is far more common than a hijack - which made this the dominant source of noise
    /// in the product. The distinction is the one the rest of the codebase already draws between
    /// "I looked and found nothing" and "I could not look"; it simply had nowhere to land.
    ///
    /// Still surfaced, still worth reading, and deliberately not counted as something to examine.
    /// </remarks>
    public bool IsUnverified =>
        Status is PersistenceStatus.FileMissing or PersistenceStatus.AccessDenied
        || ImageStatus is ImageResolutionStatus.Unresolved;

    /// <summary>
    /// True when the check completed and what it found is adverse: an unsigned or untrusted image,
    /// trust resting on a root any account can install, or a signed interpreter handed somebody
    /// else's payload.
    /// </summary>
    public bool IsAdverse =>
        Status is PersistenceStatus.Unsigned or PersistenceStatus.InvalidSignature
        // A validly signed DLL is still a finding when it is registered to load into LSASS, the
        // print spooler, the logon UI, or every process on the machine. Those surfaces are empty or
        // Microsoft-only on an ordinary machine, and somebody else's code on one of them is how an
        // attacker with a signing certificate reaches a process they could not otherwise touch.
        || PrivilegedSurfaceTriage.IsForeignCodeInAPrivilegedHost(this)
        // "Signed and trusted" is worth no more than the root it chains to, and WinVerifyTrust
        // consults CurrentUser\Root - a store any account writes with no elevation. An implant
        // signed beneath a root imported that way read SignatureValid here, which defeated the
        // central claim of the whole scanner for the price of one unprivileged store write.
        || Signature.RestsOnUserInstalledTrust
        || Abuse != InterpreterAbuse.None;
}
