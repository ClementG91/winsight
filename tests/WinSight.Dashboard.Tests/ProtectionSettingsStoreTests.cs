using WinSight.Dashboard;
using Xunit;

namespace WinSight.Dashboard.Tests;

/// <summary>
/// The remembered state of the one feature that writes into the operator's own folders.
/// </summary>
/// <remarks>
/// Nothing read or wrote the toggle before, which combined with the decoy sweep running only from
/// <c>RansomwareMonitor.Start</c> into a complete failure chain: turn protection on, reboot Windows
/// - there is no SessionEnding handler, so <c>Dispose</c> never runs - and the decoys stay in
/// Documents, Desktop and Pictures while protection comes back off, so the sweep never runs either.
/// Both the README and the tooltip promise the decoys are removed when it is turned off.
/// </remarks>
public sealed class ProtectionSettingsStoreTests
{
    private static string TempPath() =>
        Path.Combine(Path.GetTempPath(), $"winsight-protection-{Guid.NewGuid():N}.txt");

    [Fact]
    public void AChoiceSurvivesARestart()
    {
        var path = TempPath();
        try
        {
            new ProtectionSettingsStore(path).SetRansomwareProtectionEnabled(true);

            Assert.True(new ProtectionSettingsStore(path).RansomwareProtectionEnabled);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void TurningItOffIsRememberedToo()
    {
        var path = TempPath();
        try
        {
            var store = new ProtectionSettingsStore(path);
            store.SetRansomwareProtectionEnabled(true);
            store.SetRansomwareProtectionEnabled(false);

            Assert.False(new ProtectionSettingsStore(path).RansomwareProtectionEnabled);
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>
    /// Unknown means off. This is the one feature that writes to the operator's folders, so an
    /// unreadable or corrupt state file must never be read as consent to plant files.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("ransomware=maybe")]
    [InlineData("garbage")]
    public void AnUnrecognisedStateIsOff(string content)
    {
        var path = TempPath();
        File.WriteAllText(path, content);
        try
        {
            Assert.False(new ProtectionSettingsStore(path).RansomwareProtectionEnabled);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void AMissingFileIsOff() =>
        Assert.False(new ProtectionSettingsStore(TempPath()).RansomwareProtectionEnabled);

    /// <summary>An oversized file is refused rather than read into memory.</summary>
    [Fact]
    public void AnAbsurdlyLargeStateFileIsRefused()
    {
        var path = TempPath();
        File.WriteAllText(path, new string('x', 8 * 1024));
        try
        {
            Assert.False(new ProtectionSettingsStore(path).RansomwareProtectionEnabled);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
