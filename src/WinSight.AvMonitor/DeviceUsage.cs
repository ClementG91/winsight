namespace WinSight.AvMonitor;

/// <summary>A privacy-sensitive capture device WinSight watches.</summary>
public enum DeviceKind
{
    Webcam,
    Microphone,
}

/// <summary>
/// One application's recorded use of a capture device, as Windows tracks it in the
/// CapabilityAccessManager. <see cref="Active"/> means the device is in use RIGHT NOW
/// by this app (a start with no matching stop) — the OverSight-style "you're being
/// watched/heard" signal.
/// </summary>
/// <param name="Kind">Webcam or microphone.</param>
/// <param name="App">The app: a packaged app id, or a resolved desktop exe path.</param>
/// <param name="Packaged">True for a Store/packaged app, false for a desktop exe.</param>
/// <param name="LastStart">When the app last began using the device (UTC), if known.</param>
/// <param name="LastStop">When it last stopped (UTC); null while still in use.</param>
/// <param name="Active">True when the device is currently in use by this app.</param>
public sealed record DeviceUsage(
    DeviceKind Kind,
    string App,
    bool Packaged,
    DateTime? LastStart,
    DateTime? LastStop,
    bool Active);
