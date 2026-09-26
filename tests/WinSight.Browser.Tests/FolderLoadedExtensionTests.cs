using Xunit;

namespace WinSight.Browser.Tests;

/// <summary>
/// WS-48. An extension loaded with "Load unpacked" or <c>--load-extension</c> lives in a folder
/// anywhere on disk; only the profile's preferences name it. It is also how sideloaders persist,
/// writing an unpacked entry into <c>Secure Preferences</c>. A scan of the Extensions directory
/// alone never saw one.
/// </summary>
public sealed class FolderLoadedExtensionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "winsight-unpacked-" + Guid.NewGuid().ToString("N"));

    private string Profile => Path.Combine(_root, "Profile 1");

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private string Folder(string name, string manifest)
    {
        var folder = Path.Combine(_root, "dev", name);
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, "manifest.json"), manifest);
        return folder;
    }

    private void Preferences(string file, string settings)
    {
        Directory.CreateDirectory(Profile);
        File.WriteAllText(Path.Combine(Profile, file), $$"""{ "extensions": { "settings": { {{settings}} } } }""");
    }

    private static string Entry(string id, int location, string path) =>
        $$"""
        "{{id}}": { "location": {{location}}, "path": {{System.Text.Json.JsonSerializer.Serialize(path)}}, "state": 1 }
        """;

    private IReadOnlyList<BrowserExtension> Scan() =>
        new ExtensionScanner([new ExtensionScanner.Root("TestBrowser", Path.Combine(Profile, "Extensions"), Profile)])
            .Snapshot();

    [Fact]
    public void AnUnpackedExtensionIsReadFromItsFolderAndFlagged()
    {
        var folder = Folder("helper", """{ "name": "Dev Helper", "version": "0.1", "permissions": ["storage"] }""");
        Preferences("Secure Preferences", Entry("aaaabbbbccccddddeeeeffffgggghhhh", 4, folder));

        var extension = Assert.Single(Scan());

        Assert.Equal("Dev Helper", extension.Name);
        Assert.Equal(ExtensionLocation.Unpacked, extension.Location);
        Assert.Equal(folder, extension.Path);
        Assert.False(extension.HighRisk);
        Assert.True(extension.Notable);
    }

    [Fact]
    public void ACommandLineExtensionIsReportedAsSuch()
    {
        var folder = Folder("loader", """{ "name": "Loader", "version": "1", "host_permissions": ["<all_urls>"] }""");
        Preferences("Preferences", Entry("iiiijjjjkkkkllllmmmmnnnnoooopppp", 8, folder));

        var extension = Assert.Single(Scan());

        Assert.Equal(ExtensionLocation.CommandLine, extension.Location);
        Assert.True(extension.HighRisk);
    }

    [Fact]
    public void AStoreInstallInThePreferencesIsNotCountedTwice()
    {
        // A store install's path is relative to the Extensions directory, which the scan reads anyway.
        var installed = Path.Combine(Profile, "Extensions", "storeextensionid", "1.0.0_0");
        Directory.CreateDirectory(installed);
        File.WriteAllText(Path.Combine(installed, "manifest.json"), """{ "name": "Store", "version": "1.0.0" }""");
        Preferences("Secure Preferences", Entry("storeextensionid", 1, "storeextensionid\\1.0.0_0"));

        var extension = Assert.Single(Scan());

        Assert.Equal(ExtensionLocation.Profile, extension.Location);
        Assert.False(extension.Notable);
    }

    [Fact]
    public void AnEntryInBothPreferenceFilesIsReportedOnce()
    {
        var folder = Folder("twice", """{ "name": "Twice", "version": "1" }""");
        var entry = Entry("aaaabbbbccccddddeeeeffffgggghhhh", 4, folder);
        Preferences("Secure Preferences", entry);
        Preferences("Preferences", entry);

        Assert.Single(Scan());
    }

    [Fact]
    public void AnEntryWhoseFolderIsGoneIsStillReported()
    {
        var missing = Path.Combine(_root, "dev", "deleted");
        Preferences("Secure Preferences", Entry("aaaabbbbccccddddeeeeffffgggghhhh", 4, missing));

        var extension = Assert.Single(Scan());

        Assert.Equal("aaaabbbbccccddddeeeeffffgggghhhh", extension.Name);
        Assert.Null(extension.Version);
        Assert.True(extension.Notable);
    }

    [Fact]
    public void AFolderOnANetworkShareIsNamedButNeverOpened()
    {
        // TEST-NET-3: nothing answers there, and a scan that tried would stall on the SMB timeout.
        const string share = @"\\203.0.113.7\share\ext";
        Preferences("Secure Preferences", Entry("aaaabbbbccccddddeeeeffffgggghhhh", 4, share));

        var started = DateTime.UtcNow;
        var extension = Assert.Single(Scan());

        Assert.Equal(share, extension.Path);
        Assert.Null(extension.Version);
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void UnreadablePreferencesCostCoverageNotTheScan()
    {
        Preferences("Secure Preferences", "\"broken\": ");

        var acquisition = new ExtensionScanner(
            [new ExtensionScanner.Root("TestBrowser", Path.Combine(Profile, "Extensions"), Profile)])
            .SnapshotWithCoverage();

        Assert.Empty(acquisition.Items);
        Assert.Equal(1, acquisition.UnreadableSources);
    }

    [Theory]
    [InlineData("\"x\": { \"location\": \"4\", \"path\": \"C:\\\\dev\" }")]
    [InlineData("\"x\": { \"location\": 4, \"path\": \"relative\\\\dir\" }")]
    [InlineData("\"x\": { \"location\": 4 }")]
    [InlineData("\"x\": 4")]
    public void MalformedEntriesAreSkipped(string settings)
    {
        Preferences("Secure Preferences", settings);

        Assert.Empty(Scan());
    }
}
