namespace WinSight.CodeIntegrity;

/// <summary>
/// The kernel's own code-integrity options, as <c>NtQuerySystemInformation</c> reports them.
/// </summary>
/// <remarks>
/// Only the values this scan reasons about are named. The rest of the word is preserved in
/// <see cref="CodeIntegrityState.RawOptions"/> so a future reader is not lied to about what the
/// kernel actually said.
/// </remarks>
[Flags]
public enum CodeIntegrityOptions : uint
{
    None = 0,

    /// <summary>Kernel-mode code integrity is on: unsigned drivers are refused.</summary>
    Enabled = 0x0001,

    /// <summary>Test signing: the machine will load drivers signed by anybody, including self-signed.</summary>
    TestSign = 0x0002,

    /// <summary>User-mode code integrity (WDAC for applications) is on.</summary>
    UserModeEnabled = 0x0004,

    /// <summary>Kernel debugging is permitted, which relaxes what the kernel will accept.</summary>
    DebugModeEnabled = 0x0080,

    /// <summary>Hypervisor-enforced kernel code integrity — "memory integrity" in Settings.</summary>
    HypervisorEnforced = 0x0400,

    /// <summary>HVCI is in audit mode: violations are logged, not blocked.</summary>
    HypervisorAuditMode = 0x0800,

    /// <summary>HVCI strict mode.</summary>
    HypervisorStrictMode = 0x1000,
}

/// <summary>Whether a boot/kernel protection could be read at all.</summary>
public enum ProtectionReading
{
    /// <summary>The protection is on.</summary>
    On,

    /// <summary>The protection is off.</summary>
    Off,

    /// <summary>
    /// The state could not be established. Never treated as "off" — a tool that cannot read
    /// something must not report it as a weakness.
    /// </summary>
    Unknown,
}

/// <summary>
/// What the machine currently enforces about the code it will run, and about its own boot chain.
/// </summary>
/// <param name="Options">The kernel's decoded code-integrity options.</param>
/// <param name="RawOptions">The undecoded word, so nothing the kernel said is discarded.</param>
/// <param name="OptionsRead">Whether the kernel answered at all.</param>
/// <param name="SecureBoot">UEFI Secure Boot: whether the boot chain itself is verified.</param>
/// <param name="KernelDebugger">Whether a kernel debugger is attached and active.</param>
public sealed record CodeIntegrityState(
    CodeIntegrityOptions Options,
    uint RawOptions,
    bool OptionsRead,
    ProtectionReading SecureBoot,
    ProtectionReading KernelDebugger)
{
    public bool Has(CodeIntegrityOptions option) => (Options & option) == option;
}
