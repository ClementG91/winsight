using Microsoft.Win32;
using WinSight.AvMonitor;
using Xunit;

namespace WinSight.AvMonitor.Tests;

public sealed class CameraMicMonitorTests
{
    private static DeviceUsage Cam(string app, bool active) =>
        new(DeviceKind.Webcam, app, false, active ? DateTime.UtcNow : null, active ? null : DateTime.UtcNow, active);

    [Fact]
    public void Diff_DetectsActivation()
    {
        var events = CameraMicMonitor.Diff([Cam("zoom", false)], [Cam("zoom", true)]);
        var e = Assert.Single(events);
        Assert.Equal(AvEventKind.Activated, e.Kind);
        Assert.Equal("zoom", e.Usage.App);
    }

    [Fact]
    public void Diff_DetectsDeactivation()
    {
        var events = CameraMicMonitor.Diff([Cam("zoom", true)], [Cam("zoom", false)]);
        Assert.Equal(AvEventKind.Deactivated, Assert.Single(events).Kind);
    }

    [Fact]
    public void Diff_NoChange_NoEvents()
    {
        Assert.Empty(CameraMicMonitor.Diff([Cam("zoom", true)], [Cam("zoom", true)]));
    }

    [Fact]
    public void Diff_DuplicateActiveKey_DoesNotThrow()
    {
        // Same app under HKCU + HKLM, both active, must dedupe, not throw.
        Assert.Empty(CameraMicMonitor.Diff(
            [Cam("zoom", true), Cam("zoom", true)],
            [Cam("zoom", true), Cam("zoom", true)]));
    }
}

// Integration test, runs the real ConsentStore read on the Windows CI runner.
public sealed class CapabilityAccessReaderIntegrationTests
{
    [Fact]
    public void Read_DoesNotThrow_AndUsagesAreConsistent()
    {
        var usages = new CapabilityAccessReader().Read();
        Assert.NotNull(usages);
        Assert.All(usages, u =>
        {
            Assert.False(string.IsNullOrEmpty(u.App));
            if (u.Active)
            {
                Assert.NotNull(u.LastStart);
                Assert.Null(u.LastStop);
            }
        });
    }
}

public sealed class CapabilityAccessReaderTests
{
    [Fact]
    public void ReadWithCoverage_ParsesPackagedAndDesktopConsentStoreEntries()
    {
        var testRoot = $@"Software\WinSight.Tests\CapabilityAccessReader\{Guid.NewGuid():N}";
        var now = DateTime.UtcNow;
        var stopped = now.AddMinutes(1);

        try
        {
            using (var packaged = Registry.CurrentUser.CreateSubKey(
                       $@"{testRoot}\webcam\Contoso.Camera_123"))
            {
                Assert.NotNull(packaged);
                packaged.SetValue("LastUsedTimeStart", now.ToFileTimeUtc(), RegistryValueKind.QWord);
            }

            using (var desktop = Registry.CurrentUser.CreateSubKey(
                       $@"{testRoot}\microphone\NonPackaged\C:#Tools#Recorder.exe"))
            {
                Assert.NotNull(desktop);
                desktop.SetValue("LastUsedTimeStart", now.ToFileTimeUtc(), RegistryValueKind.QWord);
                desktop.SetValue("LastUsedTimeStop", stopped.ToFileTimeUtc(), RegistryValueKind.QWord);
            }

            var snapshot = new CapabilityAccessReader(testRoot).ReadWithCoverage();

            Assert.Equal(2, snapshot.Items.Count);
            Assert.Equal(0, snapshot.UnreadableSources);
            Assert.Equal(0, snapshot.UnreadableItems);

            var camera = Assert.Single(snapshot.Items, item => item.Kind == DeviceKind.Webcam);
            Assert.Equal("Contoso.Camera_123", camera.App);
            Assert.True(camera.Packaged);
            Assert.True(camera.Active);
            Assert.Equal(now, camera.LastStart);
            Assert.Null(camera.LastStop);

            var microphone = Assert.Single(
                snapshot.Items,
                item => item.Kind == DeviceKind.Microphone);
            Assert.Equal(@"C:\Tools\Recorder.exe", microphone.App);
            Assert.False(microphone.Packaged);
            Assert.False(microphone.Active);
            Assert.Equal(now, microphone.LastStart);
            Assert.Equal(stopped, microphone.LastStop);
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(testRoot, throwOnMissingSubKey: false);
        }
    }

    [Fact]
    public void Constructor_RejectsAnUnboundRegistryPath()
    {
        Assert.Throws<ArgumentException>(() => new CapabilityAccessReader(" "));
    }

    [Fact]
    public void DecodeExePath_RestoresBackslashes()
    {
        Assert.Equal(
            @"C:\Program Files\Zoom\zoom.exe",
            CapabilityAccessReader.DecodeExePath("C:#Program Files#Zoom#zoom.exe"));
    }

    [Fact]
    public void IsActive_StartWithoutStop_IsLive()
    {
        Assert.True(CapabilityAccessReader.IsActive(DateTime.UtcNow, null));
    }

    [Fact]
    public void IsActive_StartAndStop_IsNotLive()
    {
        Assert.False(CapabilityAccessReader.IsActive(DateTime.UtcNow.AddMinutes(-5), DateTime.UtcNow));
    }

    [Fact]
    public void IsActive_NeverUsed_IsNotLive()
    {
        Assert.False(CapabilityAccessReader.IsActive(null, null));
    }
}
