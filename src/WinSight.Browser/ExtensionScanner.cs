using System.Text.Json;
using WinSight.Core;

namespace WinSight.Browser;

/// <summary>
/// Scans the Chromium-family browsers' on-disk profiles for installed extensions and
/// reads each one's manifest (name, version, declared permissions). Read-only; a
/// browser or profile that isn't present is simply absent from the result, never
/// guessed. Roots are injectable so the manifest parsing is testable without a browser.
/// </summary>
public sealed class ExtensionScanner(IReadOnlyList<ExtensionScanner.Root>? roots = null)
{
    /// <summary>A browser's on-disk "Extensions" directory to scan.</summary>
    /// <param name="Browser">Friendly browser name for reporting.</param>
    /// <param name="ExtensionsDir">Path containing per-extension-id subdirectories.</param>
    public readonly record struct Root(string Browser, string ExtensionsDir);

    private readonly IReadOnlyList<Root>? _roots = roots;

    /// <summary>
    /// The standard Chromium-family extension directories under the current user's
    /// LocalAppData: <c>&lt;vendor&gt;\&lt;product&gt;\User Data\&lt;profile&gt;\Extensions</c>.
    /// </summary>
    public static IReadOnlyList<Root> DefaultWindowsRoots() =>
        DefaultWindowsRootsWithCoverage().Items;

    private static AcquisitionSnapshot<Root> DefaultWindowsRootsWithCoverage()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var browsers = new (string Name, string Base)[]
        {
            ("Chrome", System.IO.Path.Combine(local, "Google", "Chrome", "User Data")),
            ("Edge", System.IO.Path.Combine(local, "Microsoft", "Edge", "User Data")),
            ("Brave", System.IO.Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data")),
            ("Vivaldi", System.IO.Path.Combine(local, "Vivaldi", "User Data")),
            ("Opera", System.IO.Path.Combine(roaming, "Opera Software", "Opera Stable")),
        };

        var roots = new List<Root>();
        var unreadableSources = 0;
        foreach (var (name, userData) in browsers)
        {
            if (!DirectoryPresent(userData, out var userDataUnreadable))
            {
                if (userDataUnreadable)
                {
                    unreadableSources++;
                }
                continue;
            }
            // Each browser has one or more profile dirs (Default, Profile 1, …), each
            // with its own Extensions folder. Opera keeps Extensions at the top level.
            var profiles = SafeEnumerate(userData, out var profilesUnreadable);
            if (profilesUnreadable)
            {
                unreadableSources++;
                continue;
            }
            foreach (var profile in profiles.Append(userData))
            {
                var ext = System.IO.Path.Combine(profile, "Extensions");
                if (DirectoryPresent(ext, out var extensionsUnreadable))
                {
                    roots.Add(new Root(name, ext));
                }
                else if (extensionsUnreadable)
                {
                    unreadableSources++;
                }
            }
        }
        return new AcquisitionSnapshot<Root>(roots, unreadableSources);
    }

    public IReadOnlyList<BrowserExtension> Snapshot() => SnapshotWithCoverage().Items;

    public AcquisitionSnapshot<BrowserExtension> SnapshotWithCoverage()
    {
        var results = new List<BrowserExtension>();
        var rootAcquisition = _roots is null
            ? DefaultWindowsRootsWithCoverage()
            : new AcquisitionSnapshot<Root>(_roots);
        var unreadableSources = rootAcquisition.UnreadableSources;
        var unreadableItems = 0;
        foreach (var root in rootAcquisition.Items)
        {
            if (!DirectoryPresent(root.ExtensionsDir, out var rootPresenceUnreadable))
            {
                if (rootPresenceUnreadable)
                {
                    unreadableSources++;
                }
                continue;
            }
            var extensionDirectories = SafeEnumerate(root.ExtensionsDir, out var rootUnreadable);
            if (rootUnreadable)
            {
                unreadableSources++;
                continue;
            }
            foreach (var extDir in extensionDirectories)
            {
                var versionDir = LatestVersionDir(extDir, out var extensionUnreadable);
                if (extensionUnreadable)
                {
                    unreadableItems++;
                    continue;
                }
                if (versionDir is null)
                {
                    continue;
                }
                var parsed = TryParse(root.Browser, System.IO.Path.GetFileName(extDir), versionDir);
                if (parsed is not null)
                {
                    results.Add(parsed);
                }
                else
                {
                    unreadableItems++;
                }
            }
        }
        return new AcquisitionSnapshot<BrowserExtension>(
            results, unreadableSources, unreadableItems);
    }

    // Newest version subdirectory (extensions keep old versions around until GC'd).
    private static string? LatestVersionDir(string extDir, out bool unreadable)
    {
        var versions = SafeEnumerate(extDir, out unreadable);
        if (unreadable)
        {
            return null;
        }
        try
        {
            return versions
                .Where(d => File.Exists(System.IO.Path.Combine(d, "manifest.json")))
                .OrderByDescending(Directory.GetLastWriteTimeUtc)
                .FirstOrDefault();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            unreadable = true;
            return null;
        }
    }

    private static BrowserExtension? TryParse(string browser, string id, string versionDir)
    {
        try
        {
            var manifestPath = System.IO.Path.Combine(versionDir, "manifest.json");
            using var doc = JsonDocument.Parse(File.ReadAllText(manifestPath));
            var root = doc.RootElement;

            var name = ResolveName(root, versionDir, id);
            var version = root.TryGetProperty("version", out var v) ? v.GetString() : null;
            var permissions = ReadStringArray(root, "permissions")
                .Concat(ReadStringArray(root, "optional_permissions")).Distinct().ToList();
            var hosts = ReadStringArray(root, "host_permissions")
                .Concat(ReadStringArray(root, "optional_host_permissions")).Distinct().ToList();

            return new BrowserExtension(browser, id, name, version, permissions, hosts, versionDir);
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    // Extension names are often "__MSG_key__", resolve against the default-locale
    // messages.json when present, else fall back to the raw value or the id.
    private static string ResolveName(JsonElement manifest, string versionDir, string id)
    {
        var raw = manifest.TryGetProperty("name", out var n) ? n.GetString() : null;
        if (string.IsNullOrEmpty(raw))
        {
            return id;
        }
        if (!raw.StartsWith("__MSG_", StringComparison.Ordinal) || !raw.EndsWith("__", StringComparison.Ordinal))
        {
            return raw;
        }

        var key = raw.Substring("__MSG_".Length, raw.Length - "__MSG_".Length - 2);
        var locale = manifest.TryGetProperty("default_locale", out var dl) ? dl.GetString() : null;
        if (string.IsNullOrEmpty(locale))
        {
            return raw;
        }
        try
        {
            var messages = System.IO.Path.Combine(versionDir, "_locales", locale, "messages.json");
            if (!File.Exists(messages))
            {
                return raw;
            }
            using var doc = JsonDocument.Parse(File.ReadAllText(messages));
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (string.Equals(prop.Name, key, StringComparison.OrdinalIgnoreCase) &&
                    prop.Value.TryGetProperty("message", out var msg))
                {
                    return msg.GetString() ?? raw;
                }
            }
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            // Fall through to the raw token.
        }
        return raw;
    }

    private static List<string> ReadStringArray(JsonElement obj, string property)
    {
        var list = new List<string>();
        if (obj.TryGetProperty(property, out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var e in arr.EnumerateArray())
            {
                if (e.ValueKind == JsonValueKind.String && e.GetString() is { } s)
                {
                    list.Add(s);
                }
            }
        }
        return list;
    }

    private static string[] SafeEnumerate(string dir, out bool unreadable)
    {
        try
        {
            var result = Directory.GetDirectories(dir);
            unreadable = false;
            return result;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            unreadable = true;
            return [];
        }
    }

    private static bool DirectoryPresent(string path, out bool unreadable)
    {
        try
        {
            unreadable = false;
            return (File.GetAttributes(path) & FileAttributes.Directory) != 0;
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            unreadable = false;
            return false;
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            unreadable = true;
            return false;
        }
    }
}
