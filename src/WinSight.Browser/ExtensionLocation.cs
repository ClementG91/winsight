namespace WinSight.Browser;

/// <summary>Where a Chromium browser loads an extension from.</summary>
public enum ExtensionLocation
{
    /// <summary>The profile's own <c>Extensions</c> folder: a store, policy or installer install.</summary>
    Profile,

    /// <summary>
    /// A folder anywhere on disk, recorded in the profile's preferences: "Load unpacked" in developer
    /// mode, or an entry a sideloader wrote there. No store review, no update channel.
    /// </summary>
    Unpacked,

    /// <summary>A folder passed with <c>--load-extension</c> on the browser's command line.</summary>
    CommandLine,
}
