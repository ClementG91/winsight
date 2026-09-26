using WinSight.Application;
using WinSight.AvMonitor;
using WinSight.Response;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class CaptureDeviceProcessLocatorTests
{
    private static DeviceUsage Desktop(string path) =>
        new(DeviceKind.Webcam, path, Packaged: false, DateTime.UtcNow, null, Active: true);

    [Fact]
    public void ADesktopAppWithOneRunningProcessResolves()
    {
        var source = new FakeSource((10, @"C:\apps\spy.exe"));
        var inspector = new FakeInspector();
        inspector.Add(10, new ProcessIdentity(10, 1, @"C:\apps\spy.exe", "H"));

        var match = new CaptureDeviceProcessLocator(source, inspector).Locate(Desktop(@"C:\apps\spy.exe"));

        Assert.Equal(DeviceProcessResolution.Resolved, match.Resolution);
        Assert.Equal(10, Assert.Single(match.Processes).Identity.Pid);
    }

    [Fact]
    public void TwoProcessesSharingTheImageAreAmbiguous()
    {
        var source = new FakeSource((10, @"C:\apps\spy.exe"), (11, @"C:\apps\spy.exe"));
        var inspector = new FakeInspector();
        inspector.Add(10, new ProcessIdentity(10, 1, @"C:\apps\spy.exe", null));
        inspector.Add(11, new ProcessIdentity(11, 2, @"C:\apps\spy.exe", null));

        var match = new CaptureDeviceProcessLocator(source, inspector).Locate(Desktop(@"C:\apps\spy.exe"));

        Assert.Equal(DeviceProcessResolution.Ambiguous, match.Resolution);
        Assert.Equal(2, match.Processes.Count);
    }

    [Fact]
    public void AnAppNoLongerRunningIsNotRunning()
    {
        var source = new FakeSource((10, @"C:\apps\other.exe"));
        var match = new CaptureDeviceProcessLocator(source, new FakeInspector())
            .Locate(Desktop(@"C:\apps\spy.exe"));

        Assert.Equal(DeviceProcessResolution.NotRunning, match.Resolution);
        Assert.Empty(match.Processes);
    }

    [Fact]
    public void APidRecycledToAnotherImageIsNotOfferedAsTheDeviceUser()
    {
        var source = new FakeSource((10, @"C:\apps\spy.exe"));
        var inspector = new FakeInspector();
        inspector.Add(10, new ProcessIdentity(10, 99, @"C:\apps\innocent.exe", "H"));

        var match = new CaptureDeviceProcessLocator(source, inspector).Locate(Desktop(@"C:\apps\spy.exe"));

        Assert.Equal(DeviceProcessResolution.NotRunning, match.Resolution);
        Assert.Empty(match.Processes);
    }

    [Fact]
    public void APackagedAppIsReportedUnsupportedNotGuessed()
    {
        var usage = new DeviceUsage(DeviceKind.Microphone, "Microsoft.WindowsCamera_8wekyb3d8bbwe",
            Packaged: true, DateTime.UtcNow, null, Active: true);

        var match = new CaptureDeviceProcessLocator(new FakeSource(), new FakeInspector()).Locate(usage);

        Assert.Equal(DeviceProcessResolution.Unsupported, match.Resolution);
        Assert.Contains("package family", match.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TheRealSourceLocatesTheCurrentProcessByItsImagePath()
    {
        var self = Environment.ProcessPath;
        if (string.IsNullOrEmpty(self))
        {
            return;
        }
        var match = new CaptureDeviceProcessLocator(new RunningImageSource(), new Win32ProcessInspector())
            .Locate(Desktop(self));

        Assert.NotEqual(DeviceProcessResolution.NotRunning, match.Resolution);
        Assert.Contains(match.Processes, p => p.Identity.Pid == Environment.ProcessId);
    }

    private sealed class FakeSource(params (int Pid, string Path)[] items) : IRunningImageSource
    {
        public IReadOnlyList<RunningImage> All() => items.Select(i => new RunningImage(i.Pid, i.Path)).ToList();
    }

    private sealed class FakeInspector : IProcessInspector
    {
        private readonly Dictionary<int, ProcessIdentity?> _map = [];
        public void Add(int pid, ProcessIdentity id) => _map[pid] = id;
        public ProcessIdentity? Capture(int pid, bool hashImage = false) => _map.TryGetValue(pid, out var v) ? v : null;
        public string? ImageFileName(int pid) => null;
    }
}
