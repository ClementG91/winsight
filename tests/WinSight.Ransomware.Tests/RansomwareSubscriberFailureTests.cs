using Xunit;

namespace WinSight.Ransomware.Tests;

/// <summary>
/// The watcher and monitor notify from a dedicated thread. A subscriber fault used to either end the
/// process (any exception type other than IO/access/security/invalid-operation) or, for
/// InvalidOperationException, end the drain loop silently: the queue filled and every later change
/// was dropped while the monitor still looked armed.
/// </summary>
public sealed class RansomwareSubscriberFailureTests
{
    [Fact]
    public void ASubscriberFaultDoesNotStopLaterDetections()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"wsg-subfault-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var decoyA = Path.Combine(dir, "a-decoy.xlsx");
        var decoyB = Path.Combine(dir, "b-decoy.xlsx");
        File.WriteAllText(decoyA, "a");
        File.WriteAllText(decoyB, "b");
        var detections = 0;
        using var second = new ManualResetEventSlim();
        var watcher = new RansomwareFileWatcher([dir],
            path => path is not null && (path.Equals(decoyA, StringComparison.OrdinalIgnoreCase)
                                         || path.Equals(decoyB, StringComparison.OrdinalIgnoreCase)),
            new RansomwareBurstDetector(cooldown: TimeSpan.Zero));
        watcher.Detected += (_, _) =>
        {
            if (Interlocked.Increment(ref detections) == 1)
            {
                throw new InvalidOperationException("journal unavailable");
            }
            second.Set();
        };
        try
        {
            watcher.Start();
            File.AppendAllText(decoyA, "touch");
            Assert.True(SpinWait.SpinUntil(() => detections >= 1, TimeSpan.FromSeconds(5)));
            watcher.Detector.Reset();

            File.AppendAllText(decoyB, "touch");

            Assert.True(second.Wait(TimeSpan.FromSeconds(5)), "detections stopped after a subscriber fault");
            Assert.Equal(1, watcher.NotificationFailures);
            Assert.True(watcher.CoverageIsIncomplete);
        }
        finally
        {
            watcher.Dispose();
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void AMonitorSubscriberFaultStillRearmsTheDetector()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"wsg-rearm-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var manifest = Path.Combine(Path.GetTempPath(), $"wsg-manifest-{Guid.NewGuid():N}.json");
        var monitor = new RansomwareMonitor([dir], new RansomwareBurstDetector(cooldown: TimeSpan.Zero),
            new byte[32], manifest);
        var calls = 0;
        using var second = new ManualResetEventSlim();
        monitor.Detected += (_, _) =>
        {
            if (Interlocked.Increment(ref calls) == 1)
            {
                throw new NotSupportedException("first handler call fails");
            }
            second.Set();
        };
        try
        {
            monitor.Start();
            File.AppendAllText(monitor.Canaries[0], "first");
            Assert.True(SpinWait.SpinUntil(() => calls >= 1, TimeSpan.FromSeconds(5)));

            File.AppendAllText(monitor.Canaries[1], "second");

            Assert.True(second.Wait(TimeSpan.FromSeconds(5)), "the detector stayed latched after a subscriber fault");
            Assert.Equal(1, monitor.NotificationFailures);
        }
        finally
        {
            monitor.Dispose();
            Directory.Delete(dir, recursive: true);
            File.Delete(manifest);
        }
    }
}
