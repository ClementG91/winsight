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
