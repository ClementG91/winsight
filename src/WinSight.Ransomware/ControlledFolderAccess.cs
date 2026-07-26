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
    UnknownMode,
    Unavailable,
}

/// <summary>Raw runtime evidence reported by <c>MSFT_MpComputerStatus</c>.</summary>
public sealed record DefenderRuntimeEvidence(
    string? AMRunningMode,
    bool? AntivirusEnabled,
    bool? RealTimeProtectionEnabled)
{
    /// <summary>Whether all three runtime fields were available and structurally valid.</summary>
    public bool IsComplete => !string.IsNullOrWhiteSpace(AMRunningMode)
        && AntivirusEnabled.HasValue
        && RealTimeProtectionEnabled.HasValue;

    /// <summary>Whether Defender reported one of the documented operating modes this reader understands.</summary>
    public bool IsRecognizedRunningMode => AMRunningMode is not null
        && (string.Equals(AMRunningMode, "Normal", StringComparison.OrdinalIgnoreCase)
            || string.Equals(AMRunningMode, "Passive Mode", StringComparison.OrdinalIgnoreCase)
            || string.Equals(AMRunningMode, "SxS Passive Mode", StringComparison.OrdinalIgnoreCase)
            || string.Equals(AMRunningMode, "EDR Block Mode", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Positive evidence that Defender is operating normally with antivirus and real-time protection
    /// enabled. This is deliberately stricter than merely observing a configured CFA Enabled value.
    /// </summary>
    public bool SupportsControlledFolderAccessProtection => IsComplete
        && IsRecognizedRunningMode
        && string.Equals(AMRunningMode, "Normal", StringComparison.OrdinalIgnoreCase)
        && AntivirusEnabled == true
        && RealTimeProtectionEnabled == true;

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
