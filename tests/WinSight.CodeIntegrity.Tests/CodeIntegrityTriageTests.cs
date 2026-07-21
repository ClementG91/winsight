using Xunit;

namespace WinSight.CodeIntegrity.Tests;

/// <summary>
/// The judgement calls. This scan exists to reframe every other kernel finding, so what counts as
/// alarming — and, just as importantly, what does not — is worth arguing with here rather than
/// discovering on somebody's machine.
/// </summary>
public sealed class CodeIntegrityTriageTests
{
    private static CodeIntegrityState State(
        CodeIntegrityOptions options,
        bool optionsRead = true,
        ProtectionReading secureBoot = ProtectionReading.On,
        ProtectionReading kernelDebugger = ProtectionReading.Off) =>
        new(options, (uint)options, optionsRead, secureBoot, kernelDebugger);

    private static IntegrityFinding Find(CodeIntegrityState state, string name) =>
        Assert.Single(CodeIntegrityTriage.Evaluate(state), finding => finding.Name == name);

    [Fact]
    public void AHealthyMachineReportsNothingNotable()
    {
        var state = State(
            CodeIntegrityOptions.Enabled | CodeIntegrityOptions.HypervisorEnforced);

        Assert.DoesNotContain(
            CodeIntegrityTriage.Evaluate(state),
            finding => CodeIntegrityTriage.IsNotable(finding.Concern));
    }

    [Fact]
    public void TestSigningIsTheLoudestFinding()
    {
        // A machine in test signing will load a driver signed by a certificate an attacker made.
        // Every "unsigned driver" finding elsewhere has to be read against this.
        var state = State(CodeIntegrityOptions.Enabled | CodeIntegrityOptions.TestSign);

        var finding = Find(state, "test-signing");

        Assert.Equal(IntegrityConcern.Weakened, finding.Concern);
        Assert.True(CodeIntegrityTriage.IsNotable(finding.Concern));
    }

    [Fact]
    public void DriverSignatureEnforcementOffIsWeakened()
    {
        var finding = Find(State(CodeIntegrityOptions.None), "driver-signature-enforcement");

        Assert.Equal(IntegrityConcern.Weakened, finding.Concern);
    }

    [Fact]
    public void AnAttachedKernelDebuggerIsWeakened()
    {
        // It can read and rewrite kernel memory, which makes every other protection advisory.
        var state = State(CodeIntegrityOptions.Enabled, kernelDebugger: ProtectionReading.On);

        Assert.Equal(IntegrityConcern.Weakened, Find(state, "kernel-debugger").Concern);
    }

    [Fact]
    public void SecureBootOffIsHardeningNotAlarm()
    {
        // Off on a great many healthy machines, usually deliberately for dual-boot. Reporting it at
        // the same volume as test signing would train the operator to ignore this scan.
        var state = State(CodeIntegrityOptions.Enabled, secureBoot: ProtectionReading.Off);

        var finding = Find(state, "secure-boot");

        Assert.Equal(IntegrityConcern.Hardening, finding.Concern);
        Assert.True(CodeIntegrityTriage.IsNotable(finding.Concern));
    }

    [Fact]
    public void MemoryIntegrityOffIsHardeningNotAlarm()
    {
        var finding = Find(State(CodeIntegrityOptions.Enabled), "memory-integrity");

        Assert.Equal(IntegrityConcern.Hardening, finding.Concern);
    }

    [Fact]
    public void MemoryIntegrityInAuditModeIsNotTreatedAsEnforcing()
    {
        // The false-comfort case: it reads as enabled everywhere in the UI while blocking nothing.
        var state = State(
            CodeIntegrityOptions.Enabled
                | CodeIntegrityOptions.HypervisorEnforced
                | CodeIntegrityOptions.HypervisorAuditMode);

        var finding = Find(state, "memory-integrity");

        Assert.Equal(IntegrityConcern.Hardening, finding.Concern);
        Assert.Contains("AUDIT", finding.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void MemoryIntegrityEnforcingIsHealthy()
    {
        var state = State(CodeIntegrityOptions.Enabled | CodeIntegrityOptions.HypervisorEnforced);

        Assert.Equal(IntegrityConcern.Healthy, Find(state, "memory-integrity").Concern);
    }

    [Fact]
    public void AKernelThatWouldNotAnswerIsUnreadableNotOff()
    {
        // The whole point: a tool that cannot read something must not report it as a weakness.
        var state = State(CodeIntegrityOptions.None, optionsRead: false);

        Assert.Equal(IntegrityConcern.Unreadable, Find(state, "driver-signature-enforcement").Concern);
        Assert.Equal(IntegrityConcern.Unreadable, Find(state, "test-signing").Concern);
        Assert.False(CodeIntegrityTriage.IsNotable(IntegrityConcern.Unreadable));
    }

    [Fact]
    public void FirmwareWithoutSecureBootAtAllIsUnreadableNotOff()
    {
        // Legacy BIOS/CSM has no Secure Boot to be off.
        var state = State(CodeIntegrityOptions.Enabled, secureBoot: ProtectionReading.Unknown);

        Assert.Equal(IntegrityConcern.Unreadable, Find(state, "secure-boot").Concern);
    }

    [Fact]
    public void KernelDebugModeIsReportedOnlyWhenSet()
    {
        var without = CodeIntegrityTriage.Evaluate(State(CodeIntegrityOptions.Enabled));
        Assert.DoesNotContain(without, finding => finding.Name == "kernel-debug-mode");

        var with = State(CodeIntegrityOptions.Enabled | CodeIntegrityOptions.DebugModeEnabled);
        Assert.Equal(IntegrityConcern.Weakened, Find(with, "kernel-debug-mode").Concern);
    }

    [Fact]
    public void UserModeCodeIntegrityIsReportedAsHealthyWhenPresent()
    {
        var state = State(CodeIntegrityOptions.Enabled | CodeIntegrityOptions.UserModeEnabled);

        Assert.Equal(IntegrityConcern.Healthy, Find(state, "user-mode-code-integrity").Concern);
    }

    [Fact]
    public void EveryProtectionIsAlwaysReportedSoAnOperatorSeesWhatWasChecked()
    {
        // A posture report that silently omits a protection is worse than one that says "on":
        // the reader cannot tell "verified good" from "never looked".
        var names = CodeIntegrityTriage.Evaluate(State(CodeIntegrityOptions.Enabled))
            .Select(finding => finding.Name)
            .ToList();

        Assert.Contains("driver-signature-enforcement", names);
        Assert.Contains("test-signing", names);
        Assert.Contains("memory-integrity", names);
        Assert.Contains("secure-boot", names);
        Assert.Contains("kernel-debugger", names);
    }
}
