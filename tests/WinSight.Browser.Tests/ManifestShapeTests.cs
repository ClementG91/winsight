using Xunit;

namespace WinSight.Browser.Tests;

public sealed class ManifestShapeTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "winsight-manifest-" + Guid.NewGuid().ToString("N"));

    [Theory]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("42")]
    [InlineData("{\"permissions\":\"cookies\"}")]
    [InlineData("{\"permissions\":[\"cookies\",42]}")]
    [InlineData("{\"optional_permissions\":{}}")]
    [InlineData("{\"host_permissions\":null}")]
    [InlineData("{\"optional_host_permissions\":[false]}")]
    public void InvalidManifestDoesNotHideTheOtherExtensions(string manifest)
    {
        WriteManifest("broken", manifest);
        WriteManifest("valid", """
            {"name":"Valid extension","version":"1","permissions":["cookies"],"host_permissions":["<all_urls>"]}
            """);

        var snapshot = Scanner().SnapshotWithCoverage();

        var extension = Assert.Single(snapshot.Items);
        Assert.Equal("valid", extension.Id);
        Assert.True(extension.HighRisk);
        Assert.Equal(1, snapshot.UnreadableItems);
        Assert.False(snapshot.IsComplete);
    }

    /// <summary>
    /// A content script matching every site reads and rewrites every page with no host_permissions
    /// entry at all, and was graded as if it could touch nothing.
    /// </summary>
    [Theory]
    [InlineData("<all_urls>")]
    [InlineData("*://*/*")]
    [InlineData("https://*/*")]
    public void AContentScriptOnEverySiteIsBroadReach(string match)
    {
        WriteManifest("injector", $$"""
            {"name":"Injector","version":"1","content_scripts":[{"matches":["{{match}}"],"js":["c.js"]}]}
            """);

        var extension = Assert.Single(Scanner().Snapshot());

        Assert.True(extension.HighRisk);
        Assert.Contains(match, extension.HostPermissions);
    }

    [Fact]
    public void AContentScriptOnOneSiteIsNotBroadReach()
    {
        WriteManifest("narrow", """
            {"name":"Narrow","version":"1","content_scripts":[{"matches":["https://example.com/*"],"js":["c.js"]}]}
            """);

        var extension = Assert.Single(Scanner().Snapshot());

        Assert.False(extension.HighRisk);
        Assert.Contains("https://example.com/*", extension.HostPermissions);
    }

    [Theory]
    [InlineData("{\"content_scripts\":{}}")]
    [InlineData("{\"content_scripts\":[\"x\"]}")]
    [InlineData("{\"content_scripts\":[{\"matches\":\"<all_urls>\"}]}")]
    public void AMalformedContentScriptSectionIsAMalformedManifest(string manifest)
    {
        WriteManifest("broken", manifest);
        WriteManifest("valid", """{"name":"Valid","version":"1"}""");

        var snapshot = Scanner().SnapshotWithCoverage();

        Assert.Equal("valid", Assert.Single(snapshot.Items).Id);
        Assert.Equal(1, snapshot.UnreadableItems);
    }

    [Theory]
    [InlineData("\"name\":42")]
    [InlineData("\"name\":{\"message\":\"x\"}")]
    [InlineData("\"name\":\"__MSG_title__\",\"default_locale\":42")]
    [InlineData("\"name\":\"__MSG_title__\",\"default_locale\":[\"en\"]")]
    [InlineData("\"name\":\"Label\",\"version\":{}")]
    public void MistypedDisplayFieldsDoNotEraseExploitablePermissions(string displayFields)
    {
        WriteManifest("mistyped", "{" + displayFields
            + ",\"permissions\":[\"cookies\"],\"host_permissions\":[\"<all_urls>\"]}");

        var snapshot = Scanner().SnapshotWithCoverage();

        var extension = Assert.Single(snapshot.Items);
        Assert.True(extension.HighRisk);
        Assert.Contains("<all_urls>", extension.HostPermissions);
        Assert.False(string.IsNullOrEmpty(extension.Name));
    }
    [Theory]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("{\"title\":42}")]
    [InlineData("{\"title\":{\"message\":[]}}")]
    public void InvalidLocalizationPreservesThePermissionEvidence(string messages)
    {
        var version = WriteManifest("localized", """
            {"name":"__MSG_title__","default_locale":"en","permissions":["cookies"],"host_permissions":["<all_urls>"]}
            """);
        var locale = Path.Combine(version, "_locales", "en");
        Directory.CreateDirectory(locale);
        File.WriteAllText(Path.Combine(locale, "messages.json"), messages);

        var extension = Assert.Single(Scanner().Snapshot());

        Assert.Equal("__MSG_title__", extension.Name);
        Assert.True(extension.HighRisk);
    }

    [Theory]
    [InlineData("__MSG__")]
    [InlineData("__MSG___")]
    public void EmptyLocalizationTokenDoesNotTerminateTheScan(string token)
    {
        WriteManifest("short-token", System.Text.Json.JsonSerializer.Serialize(new { name = token }));

        Assert.Equal(token, Assert.Single(Scanner().Snapshot()).Name);
    }

    private ExtensionScanner Scanner() => new([new("Test", _root)]);

    private string WriteManifest(string id, string json)
    {
        var version = Path.Combine(_root, id, "1.0");
        Directory.CreateDirectory(version);
        File.WriteAllText(Path.Combine(version, "manifest.json"), json);
        return version;
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }
}
