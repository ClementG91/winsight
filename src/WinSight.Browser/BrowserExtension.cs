namespace WinSight.Browser;

/// <summary>
/// An installed browser extension (Chromium family), read from its on-disk manifest.
/// Malicious or over-permissioned extensions are a top supply-chain vector, this is
/// the unit the audit surfaces.
/// </summary>
/// <param name="Browser">Which browser it belongs to (Chrome, Edge, Brave, …).</param>
/// <param name="Id">Extension id (the directory name).</param>
/// <param name="Name">Display name from the manifest (localized when resolvable).</param>
/// <param name="Version">Extension version.</param>
/// <param name="Permissions">Declared API permissions.</param>
/// <param name="HostPermissions">Declared host/match permissions.</param>
/// <param name="Path">Path to the directory holding the manifest.</param>
public sealed record BrowserExtension(
    string Browser,
    string Id,
    string Name,
    string? Version,
    IReadOnlyList<string> Permissions,
    IReadOnlyList<string> HostPermissions,
    string Path)
{
    /// <summary>Where the browser loads it from.</summary>
    public ExtensionLocation Location { get; init; } = ExtensionLocation.Profile;

    /// <summary>
    /// Loaded from a folder rather than installed: it had no store review, and it is how
    /// sideloaders persist (developer mode, <c>--load-extension</c>, or a forged preferences entry).
    /// </summary>
    public bool LoadedFromFolder => Location != ExtensionLocation.Profile;

    /// <summary>Worth the operator's attention: broad reach, or loaded from a folder.</summary>
    public bool Notable => HighRisk || LoadedFromFolder;

    /// <summary>
    /// API permissions that grant broad reach over browsing, network or the host — the ones
    /// worth reviewing on an unfamiliar extension.
    /// </summary>
    public static readonly IReadOnlySet<string> HighRiskPermissions = new HashSet<string>(
        StringComparer.OrdinalIgnoreCase)
    {
        "<all_urls>", "tabs", "webRequest", "webRequestBlocking", "declarativeNetRequest",
        "nativeMessaging", "cookies", "history", "downloads", "debugger", "proxy",
        "management", "privacy", "contentSettings", "content_settings", "clipboardRead",
        "bookmarks", "geolocation", "desktopCapture", "pageCapture", "scripting",
    };

    /// <summary>
    /// True when the extension declares a broad-reach API permission or a wildcard host
    /// match, the classic "can read/modify everything you browse" profile.
    /// </summary>
    public bool HighRisk =>
        Permissions.Any(HighRiskPermissions.Contains) ||
        Permissions.Any(IsWildcardHost) ||
        HostPermissions.Any(IsWildcardHost);

    private static bool IsWildcardHost(string host) =>
        host is "<all_urls>" or "*://*/*" or "http://*/*" or "https://*/*" ||
        host.Contains("://*/", StringComparison.Ordinal);
}
