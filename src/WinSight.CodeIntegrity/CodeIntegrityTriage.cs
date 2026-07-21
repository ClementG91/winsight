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
/// <param name="Name">Stable identifier for the JSON contract.</param>
/// <param name="Concern">How much attention it deserves.</param>
/// <param name="Detail">Plain explanation of what this state means in practice.</param>
public sealed record IntegrityFinding(string Name, IntegrityConcern Concern, string Detail);

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
        if (state.OptionsRead && state.Has(CodeIntegrityOptions.DebugModeEnabled))
        {
            findings.Add(new IntegrityFinding(
                "kernel-debug-mode",
                IntegrityConcern.Weakened,
                "Kernel debug mode is permitted, which relaxes what the kernel will load and lets a "
                    + "debugger read and change kernel memory."));
        }
        if (state.OptionsRead && state.Has(CodeIntegrityOptions.UserModeEnabled))
        {
            findings.Add(new IntegrityFinding(
                "user-mode-code-integrity",
                IntegrityConcern.Healthy,
                "Application code integrity (WDAC) is enforced as well as driver signing."));
        }
        return findings;
    }

    private static IntegrityFinding DriverSignatureEnforcement(CodeIntegrityState state) =>
        !state.OptionsRead
            ? new IntegrityFinding(
                "driver-signature-enforcement",
                IntegrityConcern.Unreadable,
                "The kernel did not report its code-integrity options, so driver signing enforcement "
                    + "is undetermined — not the same as off.")
            : state.Has(CodeIntegrityOptions.Enabled)
                ? new IntegrityFinding(
                    "driver-signature-enforcement",
                    IntegrityConcern.Healthy,
                    "Driver signature enforcement is on: the kernel refuses unsigned drivers.")
                : new IntegrityFinding(
                    "driver-signature-enforcement",
                    IntegrityConcern.Weakened,
                    "Driver signature enforcement is OFF: the kernel will load unsigned drivers. Any "
                        + "unsigned driver reported elsewhere should be read in that light.");

    private static IntegrityFinding TestSigning(CodeIntegrityState state) =>
        !state.OptionsRead
            ? new IntegrityFinding(
                "test-signing",
                IntegrityConcern.Unreadable,
                "Whether test signing is enabled could not be established.")
            : state.Has(CodeIntegrityOptions.TestSign)
                ? new IntegrityFinding(
                    "test-signing",
                    IntegrityConcern.Weakened,
                    "TEST SIGNING is enabled: this machine will load a driver signed by anyone, "
                        + "including a certificate an attacker generated. Unless you are developing "
                        + "drivers, this should be off.")
                : new IntegrityFinding(
                    "test-signing",
                    IntegrityConcern.Healthy,
                    "Test signing is off, so a driver must carry a signature Windows trusts.");

    private static IntegrityFinding MemoryIntegrity(CodeIntegrityState state)
    {
        if (!state.OptionsRead)
        {
            return new IntegrityFinding(
                "memory-integrity",
                IntegrityConcern.Unreadable,
                "Whether memory integrity is running could not be established.");
        }
        if (!state.Has(CodeIntegrityOptions.HypervisorEnforced))
        {
            return new IntegrityFinding(
                "memory-integrity",
                IntegrityConcern.Hardening,
                "Memory integrity (HVCI) is not running. It is off on many healthy machines, but with "
                    + "it on, a driver-signing bypass alone is not enough to run code in the kernel.");
        }
        // Audit mode is worth separating: it looks enabled everywhere in the UI while enforcing
        // nothing, which is exactly the kind of false comfort this tool exists to remove.
        return state.Has(CodeIntegrityOptions.HypervisorAuditMode)
            ? new IntegrityFinding(
                "memory-integrity",
                IntegrityConcern.Hardening,
                "Memory integrity (HVCI) is in AUDIT mode: violations are logged but still allowed. "
                    + "It reads as enabled while enforcing nothing.")
            : new IntegrityFinding(
                "memory-integrity",
                IntegrityConcern.Healthy,
                state.Has(CodeIntegrityOptions.HypervisorStrictMode)
                    ? "Memory integrity (HVCI) is enforcing, in strict mode."
                    : "Memory integrity (HVCI) is enforcing.");
    }

    private static IntegrityFinding SecureBoot(CodeIntegrityState state) => state.SecureBoot switch
    {
        ProtectionReading.On => new IntegrityFinding(
            "secure-boot",
            IntegrityConcern.Healthy,
            "Secure Boot is on: the firmware verifies the boot chain before Windows starts."),
        ProtectionReading.Off => new IntegrityFinding(
            "secure-boot",
            IntegrityConcern.Hardening,
            "Secure Boot is off, so nothing verifies the boot chain before Windows starts. Often "
                + "disabled deliberately for dual-boot; if you did not turn it off, find out who did."),
        _ => new IntegrityFinding(
            "secure-boot",
            IntegrityConcern.Unreadable,
            "Secure Boot state could not be read — on a BIOS/CSM machine it does not exist at all."),
    };

    private static IntegrityFinding KernelDebugger(CodeIntegrityState state) => state.KernelDebugger switch
    {
        ProtectionReading.On => new IntegrityFinding(
            "kernel-debugger",
            IntegrityConcern.Weakened,
            "A kernel debugger is attached and active. Whoever controls it can read and change "
                + "anything in kernel memory, including every protection above."),
        ProtectionReading.Off => new IntegrityFinding(
            "kernel-debugger",
            IntegrityConcern.Healthy,
            "No kernel debugger is attached."),
        _ => new IntegrityFinding(
            "kernel-debugger",
            IntegrityConcern.Unreadable,
            "Whether a kernel debugger is attached could not be established."),
    };

    /// <summary>
    /// Whether a finding should survive the flagged-only filter.
    /// </summary>
    /// <remarks>
    /// Hardening gaps are included: this list is six lines long, and "Secure Boot is off" is
    /// precisely what an operator opening a security tool wants told. Unreadable is excluded, for
    /// the same reason an unverifiable signature is never a flag.
    /// </remarks>
    public static bool IsNotable(IntegrityConcern concern) =>
        concern is IntegrityConcern.Weakened or IntegrityConcern.Hardening;
}
