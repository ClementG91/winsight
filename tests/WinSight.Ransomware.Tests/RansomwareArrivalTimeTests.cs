using WinSight.Ransomware;

using Xunit;

namespace WinSight.Ransomware.Tests;

/// <summary>
/// The burst window measures when changes happened, not when the watcher got round to them.
/// </summary>
/// <remarks>
/// The drain thread reads each written file for entropy, one at a time, and stamped the change only
/// afterwards. Under the disk load a mass encryption causes - the case the detector exists for -
/// that read is slow, so changes that arrived within a second were stamped seconds apart and fell
/// out of the window. A deliberately slow entropy check stands in for the loaded disk: six files
/// written at once must still read as a burst in a two-second window even though scoring them takes
/// three seconds.
/// </remarks>
public sealed class RansomwareArrivalTimeTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 20, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ChangesThatArriveTogetherCountTogetherHoweverSlowlyTheyAreScored()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"wsg-arrival-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        using var detected = new ManualResetEventSlim();
        var watcher = new RansomwareFileWatcher(
            [directory],
            isCanary: _ => false,
            detector: new RansomwareBurstDetector(threshold: 6, window: TimeSpan.FromSeconds(2)),
            looksEncrypted: _ =>
            {
                Thread.Sleep(500);
                return true;
            });
        watcher.Detected += (_, _) => detected.Set();
        try
        {
            watcher.Start();
            for (var i = 0; i < 6; i++)
            {
                File.WriteAllBytes(Path.Combine(directory, $"document-{i}.bin"), [1, 2, 3]);
            }

            Assert.True(detected.Wait(TimeSpan.FromSeconds(30)),
                "six files written together were not a burst once scoring them was slow");
        }
        finally
        {
            watcher.Dispose();
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void ConcurrentCallbacksMayBeObservedOutOfTimestampOrder()
    {
        var detector = new RansomwareBurstDetector(
            threshold: 3, window: TimeSpan.FromSeconds(2), cooldown: TimeSpan.Zero);

        Assert.False(detector.Observe(RansomwareSignalKind.Rename, T0.AddMilliseconds(2), @"C:\d\later.docx"));
        Assert.False(detector.Observe(RansomwareSignalKind.Rename, T0, @"C:\d\first.docx"));
        Assert.True(detector.Observe(RansomwareSignalKind.Rename, T0.AddMilliseconds(1), @"C:\d\middle.docx"));
    }

    [Fact]
    public void AStaleCallbackThatArrivesLateDoesNotReenterTheWindow()
    {
        var detector = new RansomwareBurstDetector(
            threshold: 3, window: TimeSpan.FromSeconds(2), cooldown: TimeSpan.Zero);

        Assert.False(detector.Observe(RansomwareSignalKind.Delete, T0.AddSeconds(10), @"C:\d\recent-a.docx"));
        Assert.False(detector.Observe(RansomwareSignalKind.Delete, T0, @"C:\d\stale.docx"));
        Assert.False(detector.Observe(RansomwareSignalKind.Delete, T0.AddSeconds(11), @"C:\d\recent-b.docx"));
        Assert.Equal(2, detector.RecentCount);
    }
}
