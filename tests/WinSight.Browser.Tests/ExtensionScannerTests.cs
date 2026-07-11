using Xunit;

namespace WinSight.Browser.Tests;

/// <summary>
/// Drives the manifest parser against a fixture profile on disk — no installed browser
/// required — and smoke-checks the real default-roots scan does not throw.
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
    public void DefaultRootsSnapshot_DoesNotThrow()
    {
        // On CI there may be no browsers installed — must return a (possibly empty) list.
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
