using WinSight.Ransomware;
using Xunit;

namespace WinSight.Ransomware.Tests;

/// <summary>
/// Three ways ordinary work produced the same signal as mass encryption.
/// </summary>
/// <remarks>
/// The detector counts every rename and every delete across six recursive user folders, twelve
/// distinct files in three seconds. Measured against real work: emptying Downloads fires, a
/// <c>git clean</c> or a node_modules removal under Documents fires, a OneDrive reconciliation
/// fires. The compressed-by-design list is well built and stops photo and video extraction from
/// firing - but it omitted several formats that arrive in bulk, and it had nothing to say about a
/// file with no extension at all, which is what a git object store and a browser cache are made of.
///
/// And the latch is reset as soon as the caller has notified, so a real mass encryption - which
/// keeps producing bursts for as long as it runs - produced a stream of alerts indistinguishable
/// from a false positive repeating.
/// </remarks>
public sealed class SignalQualityTests
{
    /// <summary>
    /// Formats that are compressed or encrypted by design, so high entropy says nothing about them.
    /// Each of these arrives in bulk during ordinary developer or creative work.
    /// </summary>
    [Theory]
    [InlineData(@"C:\Users\me\Documents\repo\.git\objects\pack\pack-abc.pack")]
    [InlineData(@"C:\Users\me\Documents\app\node_modules\thing\lib.wasm")]
    [InlineData(@"C:\Users\me\Pictures\artwork.psd")]
    [InlineData(@"C:\Users\me\Documents\vm\disk.vhdx")]
    [InlineData(@"C:\Users\me\Documents\db.bak")]
    [InlineData(@"C:\Users\me\Downloads\extension.vsix")]
    public void AFormatCompressedByDesignIsNotScored(string path) =>
        Assert.False(RansomwareEntropySampler.ShouldSample(path));

    /// <summary>
    /// A content-addressed object store is excluded by its location.
    /// </summary>
    /// <remarks>
    /// The obvious move was to stop scoring files with no extension - git loose objects are exactly
    /// that. But this codebase had already decided the other way, and the reasoning holds:
    /// ransomware writes extensionless output too, and excluding by extension would trade a broad
    /// false positive for a real false negative. Naming the actual cause costs nothing on either
    /// side.
    /// </remarks>
    [Theory]
    [InlineData(@"C:\Users\me\Documents\repo\.git\objects\ab\cdef0123456789")]
    [InlineData(@"C:\Users\me\Documents\repo\.git\objects\pack\pack-abc.idx")]
    [InlineData(@"C:\Users\me\Documents\repo\.git\index")]
    public void AGitObjectStoreIsNotScored(string path) =>
        Assert.False(RansomwareEntropySampler.ShouldSample(path));

    /// <summary>
    /// The exclusion is a path segment, so neither a document called <c>.gitignore</c> nor a folder
    /// whose name merely contains "git" is swept up with it - and the working tree beside the
    /// object store is still scored, as is an extensionless file anywhere else.
    /// </summary>
    [Theory]
    [InlineData(@"C:\Users\me\Documents\repo\.gitignore")]
    [InlineData(@"C:\Users\me\Documents\github-notes\draft")]
    [InlineData(@"C:\Users\me\Documents\repo\src\main.rs")]
    [InlineData(@"C:\Users\me\Documents\payload")]
    [InlineData(@"C:\Users\me\Documents\LICENSE")]
    public void TheWorkingTreeBesideItIsStillScored(string path) =>
        Assert.True(RansomwareEntropySampler.ShouldSample(path));

    /// <summary>
    /// The cost of that decision, stated: an ordinary document is still scored, so the rule has not
    /// been widened into silence.
    /// </summary>
    [Theory]
    [InlineData(@"C:\Users\me\Documents\notes.txt")]
    [InlineData(@"C:\Users\me\Documents\report.rtf")]
    [InlineData(@"C:\Users\me\Documents\budget.csv")]
    [InlineData(@"C:\Users\me\Documents\thing.locked")]
    public void AnOrdinaryDocumentIsStillScored(string path) =>
        Assert.True(RansomwareEntropySampler.ShouldSample(path));

    /// <summary>
    /// After firing, a detector that keeps seeing bursts stays quiet and counts them. Without this
    /// a real mass encryption produced an alert stream identical to a false positive repeating.
    /// </summary>
    [Fact]
    public void ContinuingActivityProducesOneAlertAndACount()
    {
        var detector = new RansomwareBurstDetector();
        var at = DateTimeOffset.UnixEpoch;
        var alerts = 0;

        for (var burst = 0; burst < 5; burst++)
        {
            for (var file = 0; file < RansomwareBurstDetector.DefaultThreshold; file++)
            {
                if (detector.Observe(
                        RansomwareSignalKind.Rename, at, $@"C:\d\{burst}-{file}.docx"))
                {
                    alerts++;
                }
            }
            // The caller acknowledges after notifying, which is what made the stream possible.
            detector.Reset();
            at += TimeSpan.FromSeconds(4);
        }

        Assert.Equal(1, alerts);
        Assert.Equal(4, detector.SuppressedBursts);
    }

    /// <summary>
    /// Once the cooldown has passed, a new burst is a new alert. Suppression must not become
    /// silence.
    /// </summary>
    [Fact]
    public void ABurstAfterTheCooldownAlertsAgain()
    {
        var detector = new RansomwareBurstDetector(cooldown: TimeSpan.FromSeconds(30));
        var at = DateTimeOffset.UnixEpoch;

        Assert.True(Fire(detector, at));
        detector.Reset();
        Assert.False(Fire(detector, at + TimeSpan.FromSeconds(5)));
        detector.Reset();
        Assert.True(Fire(detector, at + TimeSpan.FromSeconds(31)));
    }

    /// <summary>A touched decoy is not exempt: continuing activity is one alert there too.</summary>
    [Fact]
    public void ACanaryTouchObeysTheCooldownToo()
    {
        var detector = new RansomwareBurstDetector();
        var at = DateTimeOffset.UnixEpoch;

        Assert.True(detector.Observe(RansomwareSignalKind.CanaryTouched, at));
        detector.Reset();
        Assert.False(detector.Observe(
            RansomwareSignalKind.CanaryTouched, at + TimeSpan.FromSeconds(2)));
        Assert.Equal(1, detector.SuppressedBursts);
    }

    private static bool Fire(RansomwareBurstDetector detector, DateTimeOffset at)
    {
        var fired = false;
        for (var file = 0; file < RansomwareBurstDetector.DefaultThreshold; file++)
        {
            fired |= detector.Observe(
                RansomwareSignalKind.Rename, at, $@"C:\d\{at.Ticks}-{file}.docx");
        }
        return fired;
    }
}
