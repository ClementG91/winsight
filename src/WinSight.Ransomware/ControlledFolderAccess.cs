namespace WinSight.Ransomware;

/// <summary>The configured Microsoft Defender Controlled Folder Access mode.</summary>
/// <remarks>
/// These values map directly to <c>EnableControlledFolderAccess</c>: 0 Disabled, 1 Enabled,
/// 2 Audit, 3 Block disk modification only and 4 Audit disk modification only. The two disk-only
/// modes are intentionally distinct from folder protection. <see cref="Unavailable"/> means the
/// configuration could not be read or validated; it is not a Defender configuration value.
/// </remarks>
public enum ControlledFolderAccessState
{
    Unavailable,
    Unknown,
    Disabled,
    Enabled,
    Audit,
    BlockDiskModificationOnly,
    AuditDiskModificationOnly,
}

/// <summary>What the observed configuration and runtime evidence establish for the operator.</summary>
public enum ControlledFolderAccessConcern
{
    Protecting,
    Off,
    AuditOnly,
    BlockDiskModificationOnly,
    AuditDiskModificationOnly,
    RuntimeRequirementsNotMet,
    DefenderNotRunning,
    UnknownMode,
    Unavailable,
}

/// <summary>Raw runtime evidence reported by <c>MSFT_MpComputerStatus</c>.</summary>
public sealed record DefenderRuntimeEvidence(
    string? AMRunningMode,
    bool? AntivirusEnabled,
    bool? RealTimeProtectionEnabled)
{
    private const string NormalMode = "Normal";

    private const string NotRunningMode = "Not running";

    /// <summary>
    /// Every operating mode Defender documents for <c>AMRunningMode</c>.
    /// </summary>
    /// <remarks>
    /// The spelling of the passive mode is not stable across the Windows versions WinSight supports:
    /// Microsoft's own guidance tells operators to expect <c>Normal</c>, <c>Passive</c> or
    /// <c>EDR Block Mode</c>, while side-by-side installs report <c>SxS Passive Mode</c> and some
    /// platform versions report <c>Passive Mode</c>. <c>Not running</c> is what Defender reports once
    /// its antivirus is disabled or uninstalled — the ordinary outcome of installing a non-Microsoft
    /// antivirus, and therefore a very common configuration rather than an exotic one.
    ///
    /// Accepting only a subset of these was a portability defect: an unrecognized mode is treated as
    /// a posture that could not be read, so on a perfectly healthy machine running a third-party
    /// antivirus WinSight reported "unavailable" — "we could not look" — when it had in fact looked
    /// successfully and the honest answer was "Defender is not protecting these folders". Every entry
    /// here is a successful read and must be reported as one.
    /// </remarks>
    private static readonly string[] DocumentedRunningModes =
    [
        NormalMode,
        "Passive",
        "Passive Mode",
        "SxS Passive Mode",
        "EDR Block Mode",
        NotRunningMode,
    ];

    /// <summary>Whether all three runtime fields were available and structurally valid.</summary>
    public bool IsComplete => !string.IsNullOrWhiteSpace(AMRunningMode)
        && AntivirusEnabled.HasValue
        && RealTimeProtectionEnabled.HasValue;

    /// <summary>Whether Defender reported one of the documented operating modes this reader understands.</summary>
    public bool IsRecognizedRunningMode => TrimmedRunningMode is { } mode
        && DocumentedRunningModes.Contains(mode, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Whether Defender reported that its antivirus is not running at all. Controlled Folder Access is
    /// a Defender feature, so this outranks whatever value happens to be configured for it.
    /// </summary>
    public bool IsAntivirusNotRunning =>
        string.Equals(TrimmedRunningMode, NotRunningMode, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Positive evidence that Defender is operating normally with antivirus and real-time protection
    /// enabled. This is deliberately stricter than merely observing a configured CFA Enabled value.
    /// </summary>
    public bool SupportsControlledFolderAccessProtection => IsComplete
        && IsRecognizedRunningMode
        && string.Equals(TrimmedRunningMode, NormalMode, StringComparison.OrdinalIgnoreCase)
        && AntivirusEnabled == true
        && RealTimeProtectionEnabled == true;

    // Defender is the one supplying this string; trimming keeps a stray space from downgrading a
    // successful read into "unavailable", which is the single worst way for this reader to be wrong.
    private string? TrimmedRunningMode => AMRunningMode?.Trim();
}

/// <summary>Whether Defender allowed the allowed-applications list to be enumerated.</summary>
public enum AllowedApplicationsVisibility
{
    Visible,
    RequiresElevation,
    Unavailable,
}

/// <summary>The explicitly allowed applications and the visibility of that list.</summary>
public sealed record AllowedApplications(
    AllowedApplicationsVisibility Visibility,
    IReadOnlyList<string> Applications)
{
    public static AllowedApplications None { get; } = new(AllowedApplicationsVisibility.Visible, []);

    public static AllowedApplications Unavailable { get; } = new(AllowedApplicationsVisibility.Unavailable, []);
}

/// <summary>A read-only snapshot of the configured and observed CFA posture.</summary>
public sealed record ControlledFolderAccessPosture(
    ControlledFolderAccessState State,
    DefenderRuntimeEvidence RuntimeEvidence,
    IReadOnlyList<string> ProtectedFolders,
    AllowedApplications AllowedApplications,
    ControlledFolderAccessConcern Concern)
{
    /// <summary>
    /// The successfully read raw Defender mode, when available. This is retained for an unsupported
    /// mode so the report can distinguish it from an unreadable provider response.
    /// </summary>
    public int? RawStateValue { get; init; }

    /// <summary>
    /// Compatibility summary of the full runtime evidence. It is true only when the reader observed
    /// Normal mode plus antivirus and real-time protection both enabled.
    /// </summary>
    public bool RuntimeSupportsProtection => RuntimeEvidence.SupportsControlledFolderAccessProtection;

    /// <summary>Whether this posture must remain visible in a flagged-only view.</summary>
    public bool IsNotable => ControlledFolderAccessTriage.IsNotable(Concern);

}
