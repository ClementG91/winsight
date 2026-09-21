namespace WinSight.CodeIntegrity;

/// <summary>How much a given protection's state matters.</summary>
public enum IntegrityConcern
{
    /// <summary>The protection is on. Expected, and worth showing so the operator can see it.</summary>
    Healthy,

    /// <summary>
    /// A hardening feature that is off. Common, and not evidence of anything — but it is the
    /// difference between "an attacker needs a kernel exploit" and "an attacker needs a driver".
    /// </summary>
    Hardening,

    /// <summary>
    /// A protection that should be on is off, and that materially changes what the machine will
    /// accept. This is the level that reframes every other kernel finding.
    /// </summary>
    Weakened,

    /// <summary>The state could not be read. Never counted as a weakness.</summary>
    Unreadable,
}

/// <summary>One protection, its state, and why it matters.</summary>
/// <param name="Name">Stable identifier for the protection, e.g. <c>secure-boot</c>.</param>
/// <param name="Concern">How the state should be read.</param>
/// <param name="State">
/// Stable identifier for this particular sub-case, e.g. <c>audit</c>. A protection can reach the
/// same concern by different routes - HVCI is <see cref="IntegrityConcern.Hardening"/> both when it
/// is off and when it only audits - and those are not the same sentence. The pair
/// (<paramref name="Name"/>, <paramref name="State"/>) is what a presentation layer keys on to say
/// this in the operator's language; <paramref name="Detail"/> is the English source text.
/// </param>
/// <param name="Detail">The explanation, in English.</param>
public sealed record IntegrityFinding(
    string Name, IntegrityConcern Concern, string State, string Detail);

/// <summary>
/// Reads a machine's enforcement posture and says what it means. Pure, so the judgements can be
/// argued with in tests instead of only observed on one machine.
/// </summary>
/// <remarks>
/// <b>Why this scan exists.</b> The drivers scan can say a kernel driver is unsigned; it cannot say
/// whether that matters. On a machine with test signing turned on, an unsigned driver is not an
/// anomaly at all — it is the documented consequence of a setting, and the real finding is the
/// setting. Every other kernel-level result in WinSight is read differently depending on what is
/// here, which is why this belongs in the balanced overview despite being only a handful of lines.
///
/// <b>Why "off" is not automatically alarming.</b> Secure Boot and memory integrity are off on a
/// great many perfectly healthy machines, often because the owner disabled them deliberately for
/// dual-boot or for a driver they need. Reporting those at the same volume as test signing would
/// train the operator to ignore this scan. They are separated: <see cref="IntegrityConcern.Weakened"/>
/// for states that change what the machine will load, <see cref="IntegrityConcern.Hardening"/> for a
/// defence in depth that is simply not switched on.
///
/// <b>Audit modes are read as the kernel documents them.</b> The option bits are those of
/// <c>SYSTEM_CODEINTEGRITY_INFORMATION</c> in the <c>NtQuerySystemInformation</c> reference. For
/// applications, the audit bit means executables are allowed and only logged, so WDAC in audit mode
/// is not "enforced" - which is what this scan used to say. For HVCI the audit bit is documented as
/// independent of the enabled bit: with it, HVCI enforces and also audits; without it, HVCI only
/// audits. This scan used to read "enabled plus audit" as enforcing nothing, and "audit alone" as
/// plain off.
/// </remarks>
public static class CodeIntegrityTriage
{
    public static IReadOnlyList<IntegrityFinding> Evaluate(CodeIntegrityState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        var findings = new List<IntegrityFinding>
        {
            DriverSignatureEnforcement(state),
            TestSigning(state),
            MemoryIntegrity(state),
            SecureBoot(state),
            KernelDebugger(state),
        };
        if (!state.OptionsRead)
        {
            return findings;
        }
        if (state.Has(CodeIntegrityOptions.DebugModeEnabled))
        {
            findings.Add(new IntegrityFinding(
                "kernel-debug-mode",
                IntegrityConcern.Weakened,
                "permitted",
                "Kernel debug mode is permitted, which relaxes what the kernel will load and lets a "
                    + "debugger read and change kernel memory."));
        }
        if (state.Has(CodeIntegrityOptions.FlightSigning))
        {
            findings.Add(new IntegrityFinding(
                "flight-signing",
                IntegrityConcern.Hardening,
                "on",
                "Flight signing is enabled: the kernel also accepts code signed by Microsoft's "
                    + "development root. Normal on Windows Insider builds; otherwise it should be off."));
        }
        if (state.Has(CodeIntegrityOptions.UserModeEnabled) || state.Has(CodeIntegrityOptions.UserModeAuditMode))
        {
            findings.Add(UserModeCodeIntegrity(state));
        }
        return findings;
    }

    private static IntegrityFinding DriverSignatureEnforcement(CodeIntegrityState state) =>
        !state.OptionsRead
            ? new IntegrityFinding(
                "driver-signature-enforcement",
                IntegrityConcern.Unreadable,
                "unreadable",
                "The kernel did not report its code-integrity options, so driver signing enforcement "
                    + "is undetermined — not the same as off.")
            : state.Has(CodeIntegrityOptions.Enabled)
                ? new IntegrityFinding(
                    "driver-signature-enforcement",
                    IntegrityConcern.Healthy,
                    "enforced",
                    "Driver signature enforcement is on: the kernel refuses unsigned drivers.")
                : new IntegrityFinding(
                    "driver-signature-enforcement",
                    IntegrityConcern.Weakened,
                    "off",
                    "Driver signature enforcement is OFF: the kernel will load unsigned drivers. Any "
                        + "unsigned driver reported elsewhere should be read in that light.");

    private static IntegrityFinding TestSigning(CodeIntegrityState state) =>
        !state.OptionsRead
            ? new IntegrityFinding(
                "test-signing",
                IntegrityConcern.Unreadable,
                "unreadable",
                "Whether test signing is enabled could not be established.")
            : state.Has(CodeIntegrityOptions.TestSign)
                ? new IntegrityFinding(
                    "test-signing",
                    IntegrityConcern.Weakened,
                    "on",
                    "TEST SIGNING is enabled: this machine will load a driver signed by anyone, "
                        + "including a certificate an attacker generated. Unless you are developing "
                        + "drivers, this should be off.")
                : new IntegrityFinding(
                    "test-signing",
                    IntegrityConcern.Healthy,
                    "off",
                    "Test signing is off, so a driver must carry a signature Windows trusts.");

    private static IntegrityFinding MemoryIntegrity(CodeIntegrityState state)
    {
        if (!state.OptionsRead)
        {
            return new IntegrityFinding(
                "memory-integrity",
                IntegrityConcern.Unreadable,
                "unreadable",
                "Whether memory integrity is running could not be established.");
        }
        if (!state.Has(CodeIntegrityOptions.HypervisorEnforced))
        {
            // Audit alone is worth separating: Windows Security can show memory integrity as
            // configured while nothing is enforced, which is exactly the false comfort to remove.
            return state.Has(CodeIntegrityOptions.HypervisorAuditMode)
                ? new IntegrityFinding(
                    "memory-integrity",
                    IntegrityConcern.Hardening,
                    "audit",
                    "Memory integrity (HVCI) is in AUDIT mode only: kernel components that would be "
                        + "incompatible are logged, but nothing is enforced.")
                : new IntegrityFinding(
                    "memory-integrity",
                    IntegrityConcern.Hardening,
                    "off",
                    "Memory integrity (HVCI) is not running. It is off on many healthy machines, but with "
                        + "it on, a driver-signing bypass alone is not enough to run code in the kernel.");
        }
        return state.Has(CodeIntegrityOptions.HypervisorStrictMode)
            ? new IntegrityFinding(
                "memory-integrity",
                IntegrityConcern.Healthy,
                "strict",
                "Memory integrity (HVCI) is enforcing, in strict mode.")
            : new IntegrityFinding(
                "memory-integrity",
                IntegrityConcern.Healthy,
                "enforcing",
                "Memory integrity (HVCI) is enforcing.");
    }

    private static IntegrityFinding UserModeCodeIntegrity(CodeIntegrityState state) =>
        state.Has(CodeIntegrityOptions.UserModeAuditMode)
            ? new IntegrityFinding(
                "user-mode-code-integrity",
                IntegrityConcern.Hardening,
                "audit",
                "Application code integrity (WDAC) is in AUDIT mode: policy violations are logged, "
                    + "not blocked. It reads as configured while blocking nothing.")
            : state.Has(CodeIntegrityOptions.UserModeExclusionPaths)
                ? new IntegrityFinding(
                    "user-mode-code-integrity",
                    IntegrityConcern.Hardening,
                    "exclusions",
                    "Application code integrity (WDAC) is enforced, but exclusion paths are configured "
                        + @"(HKLM\SYSTEM\CurrentControlSet\Control\CI\TRSData, TestPath): programs run from "
                        + "them are allowed even when they fail the policy.")
                : new IntegrityFinding(
                    "user-mode-code-integrity",
                    IntegrityConcern.Healthy,
                    "enforced",
                    "Application code integrity (WDAC) is enforced as well as driver signing.");

    private static IntegrityFinding SecureBoot(CodeIntegrityState state) => state.SecureBoot switch
    {
        ProtectionReading.On => new IntegrityFinding(
            "secure-boot",
            IntegrityConcern.Healthy,
            "on",
            "Secure Boot is on: the firmware verifies the boot chain before Windows starts."),
        ProtectionReading.Off => new IntegrityFinding(
            "secure-boot",
            IntegrityConcern.Hardening,
            "off",
            "Secure Boot is off, so nothing verifies the boot chain before Windows starts. Often "
                + "disabled deliberately for dual-boot; if you did not turn it off, find out who did."),
        _ => new IntegrityFinding(
            "secure-boot",
            IntegrityConcern.Unreadable,
            "unreadable",
            "Secure Boot state could not be read — on a BIOS/CSM machine it does not exist at all."),
    };

    private static IntegrityFinding KernelDebugger(CodeIntegrityState state) => state.KernelDebugger switch
    {
        ProtectionReading.On => new IntegrityFinding(
            "kernel-debugger",
            IntegrityConcern.Weakened,
            "attached",
            "A kernel debugger is attached and active. Whoever controls it can read and change "
                + "anything in kernel memory, including every protection above."),
        ProtectionReading.Off => new IntegrityFinding(
            "kernel-debugger",
            IntegrityConcern.Healthy,
            "absent",
            "No kernel debugger is attached."),
        _ => new IntegrityFinding(
            "kernel-debugger",
            IntegrityConcern.Unreadable,
            "unreadable",
            "Whether a kernel debugger is attached could not be established."),
    };

    /// <summary>
    /// Whether a finding should survive the flagged-only filter.
    /// </summary>
    /// <remarks>
    /// Hardening gaps are included: this list is a handful of lines long, and "Secure Boot is off"
    /// is precisely what an operator opening a security tool wants told. Unreadable is excluded, for
    /// the same reason an unverifiable signature is never a flag.
    /// </remarks>
    public static bool IsNotable(IntegrityConcern concern) =>
        concern is IntegrityConcern.Weakened or IntegrityConcern.Hardening;
}
