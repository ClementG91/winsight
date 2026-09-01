using System.Text.Json;

using Xunit;

namespace WinSight.Browser.Tests;

/// <summary>
/// Drives the manifest parser against a fixture profile on disk, no installed browser
/// required, and smoke-checks the real default-roots scan does not throw.
/// </summary>
public sealed class ExtensionScannerTests : IDisposable
{
    private readonly string _tempRoot = Path.Combine(Path.GetTempPath(), "winsight-ext-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public void Snapshot_ParsesManifest_ResolvesLocalizedName_AndFlagsHighRisk()
    {
        var extDir = Path.Combine(_tempRoot, "Extensions", "abcdefghijklmnop", "2.1.0");
        Directory.CreateDirectory(extDir);
        File.WriteAllText(Path.Combine(extDir, "manifest.json"), """
            {
              "manifest_version": 3,
              "name": "__MSG_extName__",
              "default_locale": "en",
              "version": "2.1.0",
              "permissions": ["storage", "cookies", "scripting"],
              "host_permissions": ["<all_urls>"]
            }
            """);
        var locale = Path.Combine(extDir, "_locales", "en");
        Directory.CreateDirectory(locale);
        File.WriteAllText(Path.Combine(locale, "messages.json"), """
            { "extName": { "message": "My Test Extension" } }
            """);

        var scanner = new ExtensionScanner(new[]
        {
            new ExtensionScanner.Root("TestBrowser", Path.Combine(_tempRoot, "Extensions")),
        });
        var extensions = scanner.Snapshot();

        var ext = Assert.Single(extensions);
        Assert.Equal("TestBrowser", ext.Browser);
        Assert.Equal("abcdefghijklmnop", ext.Id);
        Assert.Equal("My Test Extension", ext.Name);
        Assert.Equal("2.1.0", ext.Version);
        Assert.Contains("cookies", ext.Permissions);
        Assert.Contains("<all_urls>", ext.HostPermissions);
        Assert.True(ext.HighRisk); // cookies + <all_urls>
    }

    [Fact]
    public void Snapshot_LowRiskExtension_NotFlagged()
    {
        var extDir = Path.Combine(_tempRoot, "Extensions", "lowriskext", "1.0.0");
        Directory.CreateDirectory(extDir);
        File.WriteAllText(Path.Combine(extDir, "manifest.json"), """
            { "name": "Safe Theme", "version": "1.0.0", "permissions": ["storage"] }
            """);

        var scanner = new ExtensionScanner(new[]
        {
            new ExtensionScanner.Root("TestBrowser", Path.Combine(_tempRoot, "Extensions")),
        });
        var ext = Assert.Single(scanner.Snapshot());
        Assert.Equal("Safe Theme", ext.Name);
        Assert.False(ext.HighRisk);
    }

    [Fact]
    public void SnapshotWithCoverage_MalformedManifest_IsReportedAsUnreadableItem()
    {
        var extensionsDir = Path.Combine(_tempRoot, "Extensions");
        var versionDir = Path.Combine(extensionsDir, "brokenextension", "1.0.0");
        Directory.CreateDirectory(versionDir);
        File.WriteAllText(Path.Combine(versionDir, "manifest.json"), "{ not-json");

        var scanner = new ExtensionScanner(
        [
            new ExtensionScanner.Root("TestBrowser", extensionsDir),
        ]);

        var snapshot = scanner.SnapshotWithCoverage();

        Assert.Empty(snapshot.Items);
        Assert.Equal(0, snapshot.UnreadableSources);
        Assert.Equal(1, snapshot.UnreadableItems);
        Assert.False(snapshot.IsComplete);
    }

    [Fact]
    public void SnapshotWithCoverage_OversizedManifest_IsRejectedBeforeParsing()
    {
        var extensionsDir = Path.Combine(_tempRoot, "Extensions");
        var versionDir = Path.Combine(extensionsDir, "oversized", "1.0.0");
        Directory.CreateDirectory(versionDir);
        File.WriteAllText(
            Path.Combine(versionDir, "manifest.json"),
            new string(' ', 1024 * 1024 + 1));

        var snapshot = new ExtensionScanner(
        [
            new ExtensionScanner.Root("TestBrowser", extensionsDir),
        ]).SnapshotWithCoverage();

        Assert.Empty(snapshot.Items);
        Assert.Equal(1, snapshot.UnreadableItems);
        Assert.False(snapshot.IsComplete);
    }

    [Fact]
    public void Snapshot_UsesIdWhenNameIsMissing_AndMergesOptionalPermissions()
    {
        var extDir = Path.Combine(_tempRoot, "Extensions", "extension-id", "1.0.0");
        Directory.CreateDirectory(extDir);
        File.WriteAllText(Path.Combine(extDir, "manifest.json"), """
            {
              "version": "1.0.0",
              "permissions": ["storage"],
              "optional_permissions": ["storage", "tabs"],
              "host_permissions": ["https://example.test/*"],
              "optional_host_permissions": ["https://example.test/*", "https://optional.test/*"]
            }
            """);

        var scanner = new ExtensionScanner(
        [
            new ExtensionScanner.Root("TestBrowser", Path.Combine(_tempRoot, "Extensions")),
        ]);

        var extension = Assert.Single(scanner.Snapshot());

        Assert.Equal("extension-id", extension.Name);
        Assert.Equal(["storage", "tabs"], extension.Permissions);
        Assert.Equal(
            ["https://example.test/*", "https://optional.test/*"],
            extension.HostPermissions);
    }

    [Fact]
    public void Snapshot_MissingRoot_IsACompleteEmptyObservation()
    {
        var scanner = new ExtensionScanner(
        [
            new ExtensionScanner.Root("TestBrowser", Path.Combine(_tempRoot, "missing")),
        ]);

        var snapshot = scanner.SnapshotWithCoverage();

        Assert.Empty(snapshot.Items);
        Assert.True(snapshot.IsComplete);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Snapshot_UnresolvableLocalizedName_PreservesManifestToken(
        bool declaresLocale,
        bool writesMalformedMessages)
    {
        var extensionsDir = Path.Combine(_tempRoot, "Extensions");
        var versionDir = Path.Combine(extensionsDir, "localized-extension", "1.0.0");
        Directory.CreateDirectory(versionDir);
        var localeProperty = declaresLocale ? ", \"default_locale\": \"en\"" : string.Empty;
        File.WriteAllText(
            Path.Combine(versionDir, "manifest.json"),
            "{ \"name\": \"__MSG_extensionName__\"" + localeProperty + " }");
        if (writesMalformedMessages)
        {
            var localeDir = Path.Combine(versionDir, "_locales", "en");
            Directory.CreateDirectory(localeDir);
            File.WriteAllText(Path.Combine(localeDir, "messages.json"), "{ not-json");
        }

        var scanner = new ExtensionScanner(
        [
            new ExtensionScanner.Root("TestBrowser", extensionsDir),
        ]);

        var extension = Assert.Single(scanner.Snapshot());

        Assert.Equal("__MSG_extensionName__", extension.Name);
    }

    [Theory]
    [InlineData(@"\\server\share")]
    [InlineData(@"..\..\outside")]
    [InlineData(@"C:\outside")]
    [InlineData("https://example.test")]
    public void Snapshot_APathShapedLocaleIsNeverFollowed(string locale)
    {
        var extensionsDir = Path.Combine(_tempRoot, "Extensions");
        var versionDir = Path.Combine(extensionsDir, "hostile-locale", "1.0.0");
        Directory.CreateDirectory(versionDir);
        File.WriteAllText(
            Path.Combine(versionDir, "manifest.json"),
            JsonSerializer.Serialize(new
            {
                name = "__MSG_extensionName__",
                default_locale = locale,
            }));

        var scanner = new ExtensionScanner(
        [
            new ExtensionScanner.Root("TestBrowser", extensionsDir),
        ]);

        Assert.Equal("__MSG_extensionName__", Assert.Single(scanner.Snapshot()).Name);
    }

    [Fact]
    public void DefaultRootsSnapshot_DoesNotThrow()
    {
        // On CI there may be no browsers installed, must return a (possibly empty) list.
        var extensions = new ExtensionScanner().Snapshot();
        Assert.NotNull(extensions);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempRoot))
            {
                Directory.Delete(_tempRoot, recursive: true);
            }
        }
        catch (IOException)
        {
            // Best-effort cleanup.
        }
    }
}
