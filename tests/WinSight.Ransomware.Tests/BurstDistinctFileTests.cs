using WinSight.Ransomware;
using Xunit;

namespace WinSight.Ransomware.Tests;

/// <summary>
/// The burst threshold counts files, not notifications.
/// </summary>
/// <remarks>
/// Ransomware's tell is volume across <i>many</i> files. Windows reports several change
/// notifications for one file being written - a large document produces a stream of them by itself -
/// so counting raw events made a single big save look like a burst, and two Excel workbooks
/// autosaving together were enough to reach twelve. Counting distinct paths keeps the signal and
/// drops the noise without weakening the threshold.
/// </remarks>
public sealed class BurstDistinctFileTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void OneFileWrittenManyTimesIsNotABurst()
    {
        var detector = new RansomwareBurstDetector();

        for (var i = 0; i < 50; i++)
        {
            Assert.False(detector.Observe(
                RansomwareSignalKind.HighEntropyWrite,
                T0.AddMilliseconds(i * 10),
                @"C:\Users\me\Documents\big-video-export.mkv"));
        }

        Assert.Equal(1, detector.RecentCount);
        Assert.False(detector.HasFired);
    }

    [Fact]
    public void TwoWorkbooksAutosavingAreNotABurst()
    {
        var detector = new RansomwareBurstDetector();

        for (var i = 0; i < 30; i++)
        {
            detector.Observe(
                RansomwareSignalKind.HighEntropyWrite,
                T0.AddMilliseconds(i * 10),
                i % 2 == 0 ? @"C:\Users\me\Documents\a.xlsm" : @"C:\Users\me\Documents\b.xlsm");
        }

        Assert.False(detector.HasFired);
    }

    /// <summary>The real signal must still fire, or the fix traded a false positive for a miss.</summary>
    [Fact]
    public void ManyDistinctFilesInTheWindowStillFires()
    {
        var detector = new RansomwareBurstDetector();
        var fired = false;

        for (var i = 0; i < RansomwareBurstDetector.DefaultThreshold; i++)
        {
            fired |= detector.Observe(
                RansomwareSignalKind.HighEntropyWrite,
                T0.AddMilliseconds(i * 10),
                $@"C:\Users\me\Documents\file-{i}.docx.locked");
        }

        Assert.True(fired);
        Assert.True(detector.HasFired);
    }

    /// <summary>Case must not turn one file into two.</summary>
    [Fact]
    public void TheSameFileInDifferentCaseIsOneFile()
    {
        var detector = new RansomwareBurstDetector();

        detector.Observe(RansomwareSignalKind.Rename, T0, @"C:\Users\me\Documents\A.DOCX");
        detector.Observe(RansomwareSignalKind.Rename, T0, @"c:\users\me\documents\a.docx");

        Assert.Equal(1, detector.RecentCount);
    }

    /// <summary>
    /// A caller that cannot name the file must not be silently ignored, so an unnamed signal counts
    /// as its own event - which is also what keeps the old two-argument overload behaving as before.
    /// </summary>
    [Fact]
    public void UnnamedSignalsStillCount()
    {
        var detector = new RansomwareBurstDetector();
        var fired = false;

        for (var i = 0; i < RansomwareBurstDetector.DefaultThreshold; i++)
        {
            fired |= detector.Observe(RansomwareSignalKind.Delete, T0.AddMilliseconds(i * 10));
        }

        Assert.True(fired);
    }

    /// <summary>A touched decoy is high-confidence on its own and does not wait for a threshold.</summary>
    [Fact]
    public void ATouchedDecoyStillFiresImmediately() =>
        Assert.True(new RansomwareBurstDetector().Observe(
            RansomwareSignalKind.CanaryTouched, T0, @"C:\Users\me\Documents\2021_Budget_ab12cd34.xlsx"));

    /// <summary>Files touched outside the window fall out of it, distinct or not.</summary>
    [Fact]
    public void FilesOutsideTheWindowAreForgotten()
    {
        var detector = new RansomwareBurstDetector();

        for (var i = 0; i < 8; i++)
        {
            detector.Observe(RansomwareSignalKind.Delete, T0.AddSeconds(i * 10), $@"C:\a\{i}.txt");
        }

        Assert.Equal(1, detector.RecentCount);
        Assert.False(detector.HasFired);
    }
}
