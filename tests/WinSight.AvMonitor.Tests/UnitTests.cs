using WinSight.AvMonitor;
using Xunit;

namespace WinSight.AvMonitor.Tests;

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
