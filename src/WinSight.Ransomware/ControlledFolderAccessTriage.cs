namespace WinSight.Ransomware;

/// <summary>Pure interpretation of a Defender CFA configuration and its runtime evidence.</summary>
public static class ControlledFolderAccessTriage
{
    /// <summary>
    /// Determines the posture without guessing about another antivirus product. Only fully positive
    /// Defender runtime evidence can turn a configured Enabled value into <see cref="ControlledFolderAccessConcern.Protecting"/>.
    /// </summary>
    public static ControlledFolderAccessConcern Concern(
        ControlledFolderAccessState state,
        DefenderRuntimeEvidence runtimeEvidence)
    {
        ArgumentNullException.ThrowIfNull(runtimeEvidence);

        if (state == ControlledFolderAccessState.Unavailable
            || !runtimeEvidence.IsComplete
            || !runtimeEvidence.IsRecognizedRunningMode)
        {
            return ControlledFolderAccessConcern.Unavailable;
        }

        return state switch
        {
            ControlledFolderAccessState.Enabled when runtimeEvidence.SupportsControlledFolderAccessProtection =>
                ControlledFolderAccessConcern.Protecting,
            ControlledFolderAccessState.Enabled => ControlledFolderAccessConcern.RuntimeRequirementsNotMet,
            ControlledFolderAccessState.Disabled => ControlledFolderAccessConcern.Off,
            ControlledFolderAccessState.Audit => ControlledFolderAccessConcern.AuditOnly,
            ControlledFolderAccessState.BlockDiskModificationOnly =>
                ControlledFolderAccessConcern.BlockDiskModificationOnly,
            ControlledFolderAccessState.AuditDiskModificationOnly =>
                ControlledFolderAccessConcern.AuditDiskModificationOnly,
            ControlledFolderAccessState.Unknown => ControlledFolderAccessConcern.UnknownMode,
            _ => ControlledFolderAccessConcern.Unavailable,
        };
    }

    /// <summary>Whether a posture must remain visible in a flagged-only report.</summary>
    public static bool IsNotable(ControlledFolderAccessConcern concern) =>
        concern != ControlledFolderAccessConcern.Protecting;

    /// <summary>
    /// Maps documented <c>EnableControlledFolderAccess</c> values without coercion. Missing or
    /// malformed values are unavailable; a successfully read unsupported value remains explicit.
    /// </summary>
    public static ControlledFolderAccessState StateFromValue(int? value) => value switch
    {
        0 => ControlledFolderAccessState.Disabled,
        1 => ControlledFolderAccessState.Enabled,
        2 => ControlledFolderAccessState.Audit,
        3 => ControlledFolderAccessState.BlockDiskModificationOnly,
        4 => ControlledFolderAccessState.AuditDiskModificationOnly,
        null => ControlledFolderAccessState.Unavailable,
        _ => ControlledFolderAccessState.Unknown,
    };
}
