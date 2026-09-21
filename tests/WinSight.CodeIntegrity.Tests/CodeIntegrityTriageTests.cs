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

    /// <summary>
    /// The HVCI audit bit is documented as independent of the enabled bit. Alone, HVCI only
    /// audits - the false-comfort case, configured while enforcing nothing. This used to be reported
    /// as plain "off".
    /// </summary>
    [Fact]
    public void MemoryIntegrityThatOnlyAuditsIsNotTreatedAsEnforcing()
    {
        var state = State(CodeIntegrityOptions.Enabled | CodeIntegrityOptions.HypervisorAuditMode);

        var finding = Find(state, "memory-integrity");

        Assert.Equal(IntegrityConcern.Hardening, finding.Concern);
        Assert.Equal("audit", finding.State);
        Assert.Contains("AUDIT", finding.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// With the enabled bit, HVCI enforces; the audit bit adds logging for incompatible components.
    /// This used to be reported as "enforcing nothing" - a false alarm on an enforcing machine.
    /// </summary>
    [Theory]
    [InlineData(false, "enforcing")]
    [InlineData(true, "strict")]
    public void MemoryIntegrityThatEnforcesAndAlsoAuditsIsEnforcing(bool strict, string expectedState)
    {
        var options = CodeIntegrityOptions.Enabled
            | CodeIntegrityOptions.HypervisorEnforced
            | CodeIntegrityOptions.HypervisorAuditMode;
        if (strict)
        {
            options |= CodeIntegrityOptions.HypervisorStrictMode;
        }

        var finding = Find(State(options), "memory-integrity");

        Assert.Equal(IntegrityConcern.Healthy, finding.Concern);
        Assert.Equal(expectedState, finding.State);
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

        var finding = Find(state, "user-mode-code-integrity");

        Assert.Equal(IntegrityConcern.Healthy, finding.Concern);
        Assert.Equal("enforced", finding.State);
    }

    /// <summary>
    /// The false assurance this scan used to give: WDAC in audit mode allows every executable and
    /// only logs, and it was reported as enforced. Audit wins over exclusions - nothing is enforced.
    /// </summary>
    [Theory]
    [InlineData(CodeIntegrityOptions.UserModeEnabled | CodeIntegrityOptions.UserModeAuditMode)]
    [InlineData(CodeIntegrityOptions.UserModeAuditMode)]
    [InlineData(CodeIntegrityOptions.UserModeEnabled | CodeIntegrityOptions.UserModeAuditMode | CodeIntegrityOptions.UserModeExclusionPaths)]
    public void UserModeCodeIntegrityInAuditModeIsNotReportedAsEnforced(CodeIntegrityOptions userMode)
    {
        var finding = Find(State(CodeIntegrityOptions.Enabled | userMode), "user-mode-code-integrity");

        Assert.Equal(IntegrityConcern.Hardening, finding.Concern);
        Assert.Equal("audit", finding.State);
        Assert.True(CodeIntegrityTriage.IsNotable(finding.Concern));
    }

    /// <summary>Exclusion paths let anything run from them past an enforced policy.</summary>
    [Fact]
    public void UserModeCodeIntegrityWithExclusionPathsSaysSo()
    {
        var state = State(
            CodeIntegrityOptions.Enabled
                | CodeIntegrityOptions.UserModeEnabled
                | CodeIntegrityOptions.UserModeExclusionPaths);

        var finding = Find(state, "user-mode-code-integrity");

        Assert.Equal(IntegrityConcern.Hardening, finding.Concern);
        Assert.Equal("exclusions", finding.State);
        Assert.Contains("TRSData", finding.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void FlightSigningIsReportedOnlyWhenSet()
    {
        var without = CodeIntegrityTriage.Evaluate(State(CodeIntegrityOptions.Enabled));
        Assert.DoesNotContain(without, finding => finding.Name == "flight-signing");

        var with = State(CodeIntegrityOptions.Enabled | CodeIntegrityOptions.FlightSigning);
        Assert.Equal(IntegrityConcern.Hardening, Find(with, "flight-signing").Concern);
    }

    /// <summary>The kernel silent: nothing optional may be inferred from an unread word.</summary>
    [Fact]
    public void NoOptionalFindingIsReportedWhenTheKernelDidNotAnswer()
    {
        var state = State(
            CodeIntegrityOptions.UserModeEnabled | CodeIntegrityOptions.FlightSigning | CodeIntegrityOptions.DebugModeEnabled,
            optionsRead: false);

        var names = CodeIntegrityTriage.Evaluate(state).Select(finding => finding.Name).ToList();

        Assert.DoesNotContain("user-mode-code-integrity", names);
        Assert.DoesNotContain("flight-signing", names);
        Assert.DoesNotContain("kernel-debug-mode", names);
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
