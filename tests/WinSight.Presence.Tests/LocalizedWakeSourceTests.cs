using WinSight.Presence;
using Xunit;

namespace WinSight.Presence.Tests;

/// <summary>
/// Physical-presence detection on the localised Windows builds this product ships for.
/// </summary>
/// <remarks>
/// <b>The regression this pins.</b> <c>ClassifyDevice</c> matched the fragments "keyboard", "mouse"
/// and "touchpad" against the device name Windows renders in the system language. On a French or
/// Spanish machine a keyboard wake therefore fell through to <see cref="WakeCause.Device"/>,
/// <see cref="WakeSource.IndicatesPresence"/> was false, and <c>winsight presence --flagged</c> could
/// never return anything at all - the feature was inert in two of the three languages the dashboard
/// ships in. The type's own documentation had warned that matching a rendered string "would break in
/// every locale"; the code did it anyway.
/// </remarks>
public sealed class LocalizedWakeSourceTests
{
    private const int Device = 5;

    [Theory]
    // English
    [InlineData("HID Keyboard Device")]
    [InlineData("USB Input Device")]
    [InlineData("Microsoft Precision Touchpad")]
    // French, as Windows renders in-box drivers
    [InlineData("Clavier standard PS/2")]
    [InlineData("Souris HID")]
    [InlineData("Périphérique d'entrée USB")]
    [InlineData("Pavé tactile de précision Microsoft")]
    // Spanish
    [InlineData("Teclado estándar PS/2")]
    [InlineData("Ratón HID")]
    [InlineData("Dispositivo de entrada USB")]
    [InlineData("Panel táctil de precisión")]
    public void AHumanInputDeviceMeansSomebodyWasThere(string deviceName)
    {
        var cause = WakeSource.Classify(Device, deviceName);

        Assert.Equal(WakeCause.PhysicalInput, cause);
        Assert.True(WakeSource.IndicatesPresence(cause));
    }

    /// <summary>
    /// A network adapter is a packet, not a person. Getting this wrong in the other direction would
    /// raise an intruder alert on ordinary Wake-on-LAN traffic.
    /// </summary>
    [Theory]
    [InlineData("Intel(R) Ethernet Connection (7) I219-V")]
    [InlineData("Carte réseau sans fil Intel")]
    [InlineData("Adaptador de red inalámbrica")]
    [InlineData("Realtek PCIe GbE Family Controller")]
    public void ANetworkAdapterIsNotAPerson(string deviceName)
    {
        var cause = WakeSource.Classify(Device, deviceName);

        Assert.Equal(WakeCause.Network, cause);
        Assert.False(WakeSource.IndicatesPresence(cause));
    }

    /// <summary>
    /// Diacritics are folded, so one rule covers every spelling a driver may use for the same word.
    /// </summary>
    [Theory]
    [InlineData("Pave tactile")]
    [InlineData("Pavé tactile")]
    [InlineData("Peripherique d'entree")]
    [InlineData("Périphérique d’entrée")] // U+2019 apostrophe, as Windows renders it
    public void AccentsAndTypographicApostrophesDoNotDefeatTheMatch(string deviceName) =>
        Assert.Equal(WakeCause.PhysicalInput, WakeSource.Classify(Device, deviceName));

    /// <summary>
    /// A locale WinSight does not ship in degrades to "a device Windows named", never to an
    /// invented presence claim.
    /// </summary>
    [Theory]
    [InlineData("Tastatur")]
    [InlineData("Некое устройство")]
    [InlineData("Intel Management Engine")]
    public void AnUnrecognisedDeviceMakesNoPresenceClaim(string deviceName)
    {
        var cause = WakeSource.Classify(Device, deviceName);

        Assert.Equal(WakeCause.Device, cause);
        Assert.False(WakeSource.IndicatesPresence(cause));
    }

    /// <summary>The type code still decides; the name only tells one device from another.</summary>
    [Theory]
    [InlineData(0, WakeCause.Unknown)]
    [InlineData(1, WakeCause.PhysicalInput)]
    [InlineData(2, WakeCause.PhysicalInput)]
    [InlineData(4, WakeCause.Timer)]
    [InlineData(99, WakeCause.Unknown)]
    public void TheTypeCodeStillDecides(int sourceType, WakeCause expected) =>
        Assert.Equal(expected, WakeSource.Classify(sourceType, "Clavier standard PS/2"));
}
