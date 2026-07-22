namespace WinSight.Presence;

/// <summary>What brought the machine out of sleep, in the only terms Windows actually supplies.</summary>
public enum WakeCause
{
    /// <summary>Windows recorded no cause. On a real desktop this is the majority answer.</summary>
    Unknown,

    /// <summary>A keyboard, mouse, other human input device, or the power button: somebody was there.</summary>
    PhysicalInput,

    /// <summary>A network adapter — Wake-on-LAN or similar. A packet, not a person.</summary>
    Network,

    /// <summary>A scheduled wake, typically maintenance or an update.</summary>
    Timer,

    /// <summary>A device Windows named that is neither an input nor a network adapter.</summary>
    Device,
}

/// <summary>
/// Turns Windows' wake-source record into a cause an operator can act on.
/// </summary>
/// <remarks>
/// <b>The measurement that shaped this.</b> Windows logs a numeric <c>WakeSourceType</c> and, for
/// device wakes, the device's name. Measured across twelve resumes on a real desktop: seven reported
/// type 0, which Windows itself renders as <i>Unknown</i>, and five reported
/// <c>Device -Intel(R) Ethernet Connection (7) I219-V</c> — Wake-on-LAN.
///
/// That result is the whole design. "A device woke the machine" is not "somebody touched the
/// machine": on this hardware it was a network packet every single time. A check that equated them
/// would raise an intruder alert on ordinary network traffic and still say nothing about the seven
/// wakes it genuinely cannot explain. So presence is claimed only for devices a person's hands
/// operate, and everything else is reported as what Windows called it.
///
/// <b>The type code decides, not the text.</b> Matching on the rendered string would break in every
/// locale — this machine renders the label in French — and would invent a cause when Windows
/// declined to give one. The device name is consulted only to tell one kind of device from another,
/// never to overrule the code.
/// </remarks>
public static class WakeSource
{
    // Windows' WakeSourceType codes, as rendered by the operating system itself on a live machine.
    private const int Unknown = 0;
    private const int PowerButton = 1;
    private const int FixedButton = 2;
    private const int Timer = 4;
    private const int Device = 5;

    /// <summary>Fragments of a device name that mean a human operates it.</summary>
    /// <remarks>
    /// Deliberately short and specific. Every addition here converts wakes that currently read
    /// "unknown" into an accusation that somebody was present, so the bar is that the fragment
    /// cannot plausibly appear in anything else.
    /// </remarks>
    private static readonly string[] InputDeviceNames =
        ["keyboard", "mouse", "hid ", "input device", "touchpad", "trackpad"];

    /// <summary>Fragments that mean a network adapter — the common real cause of a device wake.</summary>
    private static readonly string[] NetworkDeviceNames =
        ["ethernet", "wi-fi", "wifi", "wireless", "network", "802.11", "gbe"];

    /// <summary>
    /// The cause behind a resume. <paramref name="sourceType"/> is Windows' own code;
    /// <paramref name="sourceText"/> is the device name it supplied, when it supplied one.
    /// </summary>
    public static WakeCause Classify(int sourceType, string? sourceText) => sourceType switch
    {
        PowerButton or FixedButton => WakeCause.PhysicalInput,
        Timer => WakeCause.Timer,
        Device => ClassifyDevice(sourceText),
        // Includes code 0, which Windows renders as "Unknown", and any code it may add later. An
        // unmapped code must degrade to "I do not know", never to whichever cause sits next to it.
        _ => WakeCause.Unknown,
    };

    /// <summary>Whether this cause means a person was physically at the machine.</summary>
    /// <remarks>
    /// The only cause that warrants an alert. Everything else — a timer, a packet, a device Windows
    /// named but did not explain, or no cause at all — is reported without being presented as a
    /// visitor, because a wrong name beside a security finding is worse than no name.
    /// </remarks>
    public static bool IndicatesPresence(WakeCause cause) => cause == WakeCause.PhysicalInput;

    private static WakeCause ClassifyDevice(string? sourceText)
    {
        if (string.IsNullOrWhiteSpace(sourceText))
        {
            return WakeCause.Device;
        }
        if (Matches(sourceText, InputDeviceNames))
        {
            return WakeCause.PhysicalInput;
        }
        // Checked after input on purpose: a device is far more often a network adapter than a
        // keyboard, but a name carrying both should be read as the one that implies a person.
        return Matches(sourceText, NetworkDeviceNames) ? WakeCause.Network : WakeCause.Device;
    }

    private static bool Matches(string source, string[] fragments) =>
        fragments.Any(fragment => source.Contains(fragment, StringComparison.OrdinalIgnoreCase));
}
