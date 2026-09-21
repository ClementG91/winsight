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
    private const long MaximumJsonBytes = 1024 * 1024;

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
        // Pre-release channels install side by side with their own user data, and are where a
        // developer or tester is most likely to have loaded something unreviewed; they were not read.
        var browsers = new (string Name, string Base)[]
        {
            ("Chrome", System.IO.Path.Combine(local, "Google", "Chrome", "User Data")),
            ("Chrome Beta", System.IO.Path.Combine(local, "Google", "Chrome Beta", "User Data")),
            ("Chrome Dev", System.IO.Path.Combine(local, "Google", "Chrome Dev", "User Data")),
            ("Chrome Canary", System.IO.Path.Combine(local, "Google", "Chrome SxS", "User Data")),
            ("Chromium", System.IO.Path.Combine(local, "Chromium", "User Data")),
            ("Edge", System.IO.Path.Combine(local, "Microsoft", "Edge", "User Data")),
            ("Edge Beta", System.IO.Path.Combine(local, "Microsoft", "Edge Beta", "User Data")),
            ("Edge Dev", System.IO.Path.Combine(local, "Microsoft", "Edge Dev", "User Data")),
            ("Edge Canary", System.IO.Path.Combine(local, "Microsoft", "Edge SxS", "User Data")),
            ("Brave", System.IO.Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data")),
            ("Brave Beta", System.IO.Path.Combine(local, "BraveSoftware", "Brave-Browser-Beta", "User Data")),
            ("Brave Nightly", System.IO.Path.Combine(local, "BraveSoftware", "Brave-Browser-Nightly", "User Data")),
            ("Vivaldi", System.IO.Path.Combine(local, "Vivaldi", "User Data")),
            ("Opera", System.IO.Path.Combine(roaming, "Opera Software", "Opera Stable")),
            ("Opera GX", System.IO.Path.Combine(roaming, "Opera Software", "Opera GX Stable")),
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
                .Where(d => AutomaticFileAccess.FileExists(
                    System.IO.Path.Combine(d, "manifest.json")))
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
            using var doc = ParseJson(manifestPath);
            if (doc is null)
            {
                return null;
            }
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var name = ResolveName(root, versionDir, id);
            // Display fields only. A mistyped label must not cost the permission evidence below.
            var version = DisplayString(root, "version");
            var permissions = ReadStringArray(root, "permissions")
                .Concat(ReadStringArray(root, "optional_permissions")).Distinct().ToList();
            // Content-script match patterns are host access too: an extension whose content script
            // matches <all_urls> reads and rewrites every page without any host_permissions entry,
            // and was graded as if it could touch nothing.
            var hosts = ReadStringArray(root, "host_permissions")
                .Concat(ReadStringArray(root, "optional_host_permissions"))
                .Concat(ReadContentScriptMatches(root))
                .Distinct()
                .ToList();

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
        var raw = DisplayString(manifest, "name");
        if (string.IsNullOrEmpty(raw))
        {
            return id;
        }
        if (!raw.StartsWith("__MSG_", StringComparison.Ordinal) || !raw.EndsWith("__", StringComparison.Ordinal))
        {
            return raw;
        }

        if (raw.Length <= "__MSG_".Length + 2)
        {
            return raw;
        }
        var key = raw.Substring("__MSG_".Length, raw.Length - "__MSG_".Length - 2);
        var locale = DisplayString(manifest, "default_locale");
        if (string.IsNullOrEmpty(locale))
        {
            return raw;
        }
        if (locale.Length > 35 || locale.Any(character =>
                !char.IsAsciiLetterOrDigit(character) && character is not '_' and not '-'))
        {
            // A manifest is attacker-controlled evidence. Path.Combine discards its earlier parts
            // when a later component is absolute, so an UNC "locale" would otherwise turn this
            // no-network scan into a read from that server. Chromium locale names are simple BCP
            // 47-style directory tokens (en, en_US, pt-BR), never paths.
            return raw;
        }
        try
        {
            var messages = System.IO.Path.Combine(versionDir, "_locales", locale, "messages.json");
            if (!AutomaticFileAccess.FileExists(messages))
            {
                return raw;
            }
            using var doc = ParseJson(messages);
            if (doc is null || doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return raw;
            }
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (string.Equals(prop.Name, key, StringComparison.OrdinalIgnoreCase)
                    && prop.Value.ValueKind == JsonValueKind.Object)
                {
                    return ReadOptionalString(prop.Value, "message") ?? raw;
                }
            }
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            // Fall through to the raw token.
        }
        return raw;
    }

    // Lenient read for a label: absent, null or mistyped all mean "no usable value".
    private static string? DisplayString(JsonElement obj, string property) =>
        obj.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string? ReadOptionalString(JsonElement obj, string property)
    {
        if (!obj.TryGetProperty(property, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        return value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : throw new JsonException("An extension string field has an invalid type.");
    }

    /// <summary>
    /// The <c>matches</c> patterns of every entry in <c>content_scripts</c>. A malformed section is
    /// a malformed manifest, as for the permission arrays.
    /// </summary>
    private static List<string> ReadContentScriptMatches(JsonElement manifest)
    {
        var matches = new List<string>();
        if (!manifest.TryGetProperty("content_scripts", out var scripts))
        {
            return matches;
        }
        if (scripts.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException("An extension's content_scripts field is not an array.");
        }
        foreach (var script in scripts.EnumerateArray())
        {
            if (script.ValueKind != JsonValueKind.Object)
            {
                throw new JsonException("An extension content script is not an object.");
            }
            matches.AddRange(ReadStringArray(script, "matches"));
        }
        return matches;
    }

    private static List<string> ReadStringArray(JsonElement obj, string property)
    {
        var list = new List<string>();
        if (!obj.TryGetProperty(property, out var arr))
        {
            return list;
        }
        if (arr.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException("An extension permission field is not an array.");
        }
        foreach (var element in arr.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.String)
            {
                throw new JsonException("An extension permission is not a string.");
            }
            list.Add(element.GetString()!);
        }
        return list;
    }

    private static string[] SafeEnumerate(string dir, out bool unreadable)
    {
        try
        {
            using var lease = AutomaticFileAccess.TryAcquire(dir);
            if (lease is null || !lease.IsDirectory)
            {
                unreadable = true;
                return [];
            }
            var result = Directory.GetDirectories(lease.FullPath);
            if (!lease.IsCurrent())
            {
                unreadable = true;
                return [];
            }
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
            using var lease = AutomaticFileAccess.TryAcquire(path);
            if (lease is null)
            {
                unreadable = !AutomaticFileAccess.IsLocal(path);
                return false;
            }
            unreadable = false;
            return lease.IsDirectory && lease.IsCurrent();
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

    private static JsonDocument? ParseJson(string path)
    {
        using var lease = AutomaticFileAccess.TryAcquire(path);
        if (lease is null || lease.IsDirectory || lease.Length > MaximumJsonBytes)
        {
            return null;
        }
        using var stream = lease.OpenRead();
        var document = JsonDocument.Parse(stream);
        if (lease.IsCurrent())
        {
            return document;
        }
        document.Dispose();
        return null;
    }
}
