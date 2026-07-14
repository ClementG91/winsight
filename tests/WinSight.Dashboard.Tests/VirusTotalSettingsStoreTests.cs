using Xunit;

namespace WinSight.Dashboard.Tests;

[Collection(LocalizationCollection.Name)]
public sealed class VirusTotalSettingsStoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "winsight-dashboard-tests",
        Guid.NewGuid().ToString("N"));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("too-short")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa invalid")]
    public void Validation_RejectsMissingOrUnsafeValues(string? key)
    {
        Assert.False(VirusTotalSettingsStore.IsPlausibleApiKey(key));
    }

    [Fact]
    public void Validation_AcceptsCurrentVirusTotalKeyShape()
    {
        Assert.True(VirusTotalSettingsStore.IsPlausibleApiKey(new string('a', 64)));
    }

    [Fact]
    public void Store_EncryptsRoundTripsAndClearsForCurrentWindowsUser()
    {
        var path = Path.Combine(_directory, "key.bin");
        var store = new VirusTotalSettingsStore(path);
        var key = new string('b', 64);

        store.Save(key);

        Assert.Equal(key, store.LoadStoredKey());
        Assert.False(File.ReadAllBytes(path).AsSpan().SequenceEqual(System.Text.Encoding.UTF8.GetBytes(key)));
        store.Clear();
        Assert.Null(store.LoadStoredKey());
    }

    [Fact]
    public void Store_RejectsOversizedProtectedPayloadBeforeReadingIt()
    {
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, "oversized.bin");
        File.WriteAllBytes(path, new byte[9 * 1024]);

        Assert.Null(new VirusTotalSettingsStore(path).LoadStoredKey());
    }

    [Fact]
    public void EnvironmentConfiguration_RemainsAuthoritativeForTheSession()
    {
        var original = Environment.GetEnvironmentVariable(VirusTotalSettingsStore.EnvironmentVariable);
        var externalKey = new string('c', 64);
        var storedKey = new string('d', 64);
        try
        {
            Environment.SetEnvironmentVariable(
                VirusTotalSettingsStore.EnvironmentVariable,
                externalKey,
                EnvironmentVariableTarget.Process);
            var store = new VirusTotalSettingsStore(Path.Combine(_directory, "override.bin"));
            store.ApplyToCurrentProcess();
            store.Save(storedKey);
            store.ApplySavedKeyToCurrentProcess(storedKey);
            store.DisableForCurrentProcess();

            Assert.True(store.EnvironmentOverrideActive);
            Assert.Equal(externalKey, Environment.GetEnvironmentVariable(VirusTotalSettingsStore.EnvironmentVariable));
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                VirusTotalSettingsStore.EnvironmentVariable,
                original,
                EnvironmentVariableTarget.Process);
        }
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (DirectoryNotFoundException)
        {
        }
    }
}
