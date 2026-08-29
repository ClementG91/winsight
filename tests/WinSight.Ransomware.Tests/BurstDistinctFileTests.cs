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

    /// <summary>
    /// The window does not grow without limit before the detector fires.
    /// </summary>
    /// <remarks>
    /// The class documented itself as bounded, and it was - but only after firing. Before that,
    /// every notification inside the window was retained, and Windows reports many notifications for
    /// one file being written. A process rewriting one file in a loop grows the window for as long
    /// as it stays below the distinct-file threshold, which is the shape of a program that is not
    /// ransomware at all.
    ///
    /// Only duplicates are discarded, so what this must also prove is that the count the threshold
    /// is compared against is unaffected.
    /// </remarks>
    [Fact]
    public void RepeatedWritesToOneFileNeitherFireNorGrowWithoutLimit()
    {
        var detector = new RansomwareBurstDetector();
        var at = DateTimeOffset.UnixEpoch;

        for (var index = 0; index < 50_000; index++)
        {
            Assert.False(detector.Observe(
                RansomwareSignalKind.HighEntropyWrite, at, @"C:\Users\me\Documents\one.docx"));
        }

        Assert.Equal(1, detector.RecentCount);
        Assert.False(detector.HasFired);
    }

    /// <summary>
    /// A burst still fires after a flood of duplicates has driven the window past its cap. The
    /// trimming must not be able to discard the evidence.
    /// </summary>
    [Fact]
    public void ABurstIsStillDetectedAfterAFloodOfDuplicates()
    {
        var detector = new RansomwareBurstDetector();
        var at = DateTimeOffset.UnixEpoch;

        for (var index = 0; index < 20_000; index++)
        {
            detector.Observe(RansomwareSignalKind.HighEntropyWrite, at, @"C:\noise\same.tmp");
        }

        // It fires exactly once, on whichever file crosses the threshold, so what is asserted is
        // that it fired at all - not that the last call was the one that did.
        var fired = false;
        for (var index = 0; index < RansomwareBurstDetector.DefaultThreshold; index++)
        {
            fired |= detector.Observe(
                RansomwareSignalKind.HighEntropyWrite, at, $@"C:\Users\me\Documents\{index}.docx");
        }

        Assert.True(fired);
        Assert.True(detector.HasFired);
    }

    /// <summary>
    /// The work per observation must not grow with the window. Measured rather than asserted about:
    /// the distinct count used to be rebuilt by walking the whole window and allocating a fresh set
    /// on every single event, so the cost of a burst grew with its square - and the moment that
    /// matters is mass encryption, when thousands of notifications arrive inside three seconds.
    ///
    /// The bound is deliberately generous. It is not a benchmark; it fails only on a return to
    /// quadratic behaviour, which at this scale is a difference of orders of magnitude.
    /// </summary>
    [Fact]
    public void TheCostOfAnObservationDoesNotGrowWithTheWindow()
    {
        var detector = new RansomwareBurstDetector(threshold: int.MaxValue);
        var at = DateTimeOffset.UnixEpoch;
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        for (var index = 0; index < 100_000; index++)
        {
            detector.Observe(RansomwareSignalKind.Rename, at, $@"C:\d\{index}.docx");
        }
        stopwatch.Stop();

        Assert.True(
            stopwatch.Elapsed < TimeSpan.FromSeconds(10),
            $"100k observations took {stopwatch.Elapsed}; the per-event cost is growing with the window");
    }
}
