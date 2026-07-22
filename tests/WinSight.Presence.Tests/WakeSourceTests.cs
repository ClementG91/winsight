using WinSight.Presence;

using Xunit;

namespace WinSight.Presence.Tests;

/// <summary>
/// What woke the machine — the one question a physical-access check turns on.
/// </summary>
/// <remarks>
/// <b>Measured before it was designed, and the measurement changed the design.</b> Windows records a
/// numeric <c>WakeSourceType</c> plus a device name, not free text. On a real desktop over twelve
/// resumes: seven reported <c>Unknown</c> and five reported a <i>device</i> that was an Ethernet
/// adapter — Wake-on-LAN, not a person. So "a device woke it" is emphatically not "somebody touched
/// it", and a check that equated the two would accuse a network packet of being an intruder while
/// staying silent about the majority it cannot explain at all.
///
/// The rule therefore only ever claims physical presence for a human input device, and reports
/// everything else as what Windows itself called it. Saying "unknown" seven times out of twelve is
/// the honest output here; inventing a person to fill the gap is the failure this project exists to
/// avoid.
/// </remarks>
public sealed class WakeSourceTests
{
    // ---- Windows' own type codes, as observed on a live machine -------------------------------

    [Fact]
    public void TypeZeroIsUnknown()
        => Assert.Equal(WakeCause.Unknown, WakeSource.Classify(0, null));

    [Fact]
    public void TypeZeroStaysUnknownEvenWhenSomeTextCameWithIt()
    {
        // Windows renders type 0 as "Unknown" whatever else is in the record; trusting stray text
        // over the type code would manufacture a cause the operating system declined to give.
        Assert.Equal(WakeCause.Unknown, WakeSource.Classify(0, "something"));
    }

    // ---- A device is only a person when it is one an operator's hands touch -------------------

    [Theory]
    [InlineData("HID Keyboard Device")]
    [InlineData("USB Input Device")]
    [InlineData("Microsoft Mouse and Keyboard Detection Driver")]
    [InlineData("Logitech USB Optical Mouse")]
    public void AHumanInputDeviceIsPhysicalPresence(string source)
        => Assert.Equal(WakeCause.PhysicalInput, WakeSource.Classify(5, source));

    /// <summary>
    /// A network adapter waking the machine is not a person, and this is the common real case.
    /// </summary>
    /// <remarks>
    /// Five of the twelve resumes measured on the development desktop were
    /// "Device -Intel(R) Ethernet Connection (7) I219-V". Classing those as physical presence would
    /// make this check cry wolf every time Wake-on-LAN fired.
    /// </remarks>
    [Theory]
    [InlineData("Intel(R) Ethernet Connection (7) I219-V")]
    [InlineData("Realtek PCIe GbE Family Controller")]
    [InlineData("Intel(R) Wi-Fi 6 AX201 160MHz")]
    public void ANetworkAdapterIsNotAPerson(string source)
        => Assert.Equal(WakeCause.Network, WakeSource.Classify(5, source));

    [Fact]
    public void ADeviceThatIsNeitherInputNorNetworkIsReportedAsADeviceNotGuessedAt()
    {
        // Naming it a person would be a false accusation; calling it unknown would throw away what
        // Windows did tell us. It is a device, and the operator is told which one.
        Assert.Equal(WakeCause.Device, WakeSource.Classify(5, "Standard SATA AHCI Controller"));
    }

    [Fact]
    public void ATimerWakeIsScheduledWorkNotAVisitor()
        => Assert.Equal(WakeCause.Timer, WakeSource.Classify(4, @"NT TASK\Microsoft\Windows\UpdateOrchestrator\Reboot"));

    [Fact]
    public void APowerButtonPressIsPhysicalPresence()
        => Assert.Equal(WakeCause.PhysicalInput, WakeSource.Classify(1, null));

    // ---- Only physical presence is worth an alert ---------------------------------------------

    [Theory]
    [InlineData(WakeCause.PhysicalInput, true)]
    [InlineData(WakeCause.Network, false)]
    [InlineData(WakeCause.Timer, false)]
    [InlineData(WakeCause.Device, false)]
    [InlineData(WakeCause.Unknown, false)]
    public void OnlyAHumanTouchIsNotable(WakeCause cause, bool expected)
        => Assert.Equal(expected, WakeSource.IndicatesPresence(cause));

    /// <summary>
    /// The classifier must not degrade into "everything is a person".
    /// </summary>
    /// <remarks>
    /// Without this, a rule that returned <see cref="WakeCause.PhysicalInput"/> for anything would
    /// pass every positive test in this file. On the machine this was written against the correct
    /// answer is zero physical wakes out of twelve, so the negative cases are the load-bearing ones.
    /// </remarks>
    [Fact]
    public void TheClassifierIsNotUniformlyOptimistic()
    {
        WakeCause[] causes =
        [
            WakeSource.Classify(0, null),
            WakeSource.Classify(4, "NT TASK"),
            WakeSource.Classify(5, "Intel(R) Ethernet Connection (7) I219-V"),
            WakeSource.Classify(5, "HID Keyboard Device"),
        ];

        Assert.Equal(causes.Length, causes.Distinct().Count());
        Assert.Single(causes, WakeSource.IndicatesPresence);
    }

    [Fact]
    public void AnUnrecognisedTypeCodeIsUnknownRatherThanAGuess()
    {
        // Windows may add codes. An unmapped one must degrade to "I do not know", never to a cause
        // that happens to sit next to it in the enum.
        Assert.Equal(WakeCause.Unknown, WakeSource.Classify(99, "whatever"));
    }
}
