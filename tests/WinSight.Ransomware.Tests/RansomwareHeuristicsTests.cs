using System.Text;

using WinSight.Ransomware;

using Xunit;

namespace WinSight.Ransomware.Tests;

public sealed class ShannonEntropyTests
{
    [Fact]
    public void BitsPerByte_Empty_IsZero() =>
        Assert.Equal(0.0, ShannonEntropy.BitsPerByte(ReadOnlySpan<byte>.Empty));

    [Fact]
    public void BitsPerByte_SingleRepeatedByte_IsZero()
    {
        var data = new byte[1024]; // all zero
        Assert.Equal(0.0, ShannonEntropy.BitsPerByte(data));
        Assert.False(ShannonEntropy.LooksEncrypted(data));
    }

    [Fact]
    public void BitsPerByte_UniformOverAllValues_IsEight_AndLooksEncrypted()
    {
        var data = new byte[1024];
        for (var i = 0; i < data.Length; i++)
        {
            data[i] = (byte)(i % 256); // each of 256 values appears equally -> entropy = log2(256) = 8
        }

        Assert.Equal(8.0, ShannonEntropy.BitsPerByte(data), precision: 6);
        Assert.True(ShannonEntropy.LooksEncrypted(data));
    }

    [Fact]
    public void LooksEncrypted_PlainText_IsFalse()
    {
        var text = string.Concat(Enumerable.Repeat("the quick brown fox jumps over the lazy dog. ", 20));
        var data = Encoding.ASCII.GetBytes(text);

        Assert.True(data.Length >= ShannonEntropy.MinimumSampleBytes);
        Assert.True(ShannonEntropy.BitsPerByte(data) < ShannonEntropy.EncryptedThreshold);
        Assert.False(ShannonEntropy.LooksEncrypted(data));
    }

    [Fact]
    public void LooksEncrypted_TooSmallASample_IsFalse_EvenIfHighEntropy()
    {
        var data = new byte[128];
        for (var i = 0; i < data.Length; i++)
        {
            data[i] = (byte)(i * 2); // high per-byte variety, but below the minimum sample size
        }

        Assert.False(ShannonEntropy.LooksEncrypted(data));
    }
}

public sealed class RansomwareBurstDetectorTests
{
    private static readonly DateTimeOffset T0 = new(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Observe_BelowThreshold_DoesNotFire()
    {
        var detector = new RansomwareBurstDetector(threshold: 3, window: TimeSpan.FromSeconds(1));

        Assert.False(detector.Observe(RansomwareSignalKind.Rename, T0));
        Assert.False(detector.Observe(RansomwareSignalKind.Rename, T0.AddMilliseconds(100)));
        Assert.False(detector.HasFired);
    }

    [Fact]
    public void Observe_ThresholdWithinWindow_FiresExactlyOnce()
    {
        var detector = new RansomwareBurstDetector(threshold: 3, window: TimeSpan.FromSeconds(1));

        Assert.False(detector.Observe(RansomwareSignalKind.HighEntropyWrite, T0));
        Assert.False(detector.Observe(RansomwareSignalKind.HighEntropyWrite, T0.AddMilliseconds(300)));
        Assert.True(detector.Observe(RansomwareSignalKind.HighEntropyWrite, T0.AddMilliseconds(600)));
        // Already fired: further signals do not re-fire until Reset.
        Assert.False(detector.Observe(RansomwareSignalKind.HighEntropyWrite, T0.AddMilliseconds(700)));
        Assert.True(detector.HasFired);
    }

    [Fact]
    public void Observe_EventsSpreadBeyondWindow_NeverFire()
    {
        var detector = new RansomwareBurstDetector(threshold: 3, window: TimeSpan.FromSeconds(1));

        Assert.False(detector.Observe(RansomwareSignalKind.Delete, T0));
        Assert.False(detector.Observe(RansomwareSignalKind.Delete, T0.AddSeconds(2)));
        Assert.False(detector.Observe(RansomwareSignalKind.Delete, T0.AddSeconds(4)));

        Assert.Equal(1, detector.RecentCount); // old events fell out of the window
        Assert.False(detector.HasFired);
    }

    [Fact]
    public void Observe_CanaryTouched_FiresImmediately()
    {
        var detector = new RansomwareBurstDetector();

        Assert.True(detector.Observe(RansomwareSignalKind.CanaryTouched, T0));
        Assert.True(detector.HasFired);
    }

    [Fact]
    public void Reset_ReArmsForALaterBurst()
    {
        var detector = new RansomwareBurstDetector(threshold: 2, window: TimeSpan.FromSeconds(1));
        detector.Observe(RansomwareSignalKind.Rename, T0);
        Assert.True(detector.Observe(RansomwareSignalKind.Rename, T0.AddMilliseconds(100)));

        detector.Reset();
        Assert.False(detector.HasFired);
        Assert.Equal(0, detector.RecentCount);

        detector.Observe(RansomwareSignalKind.Rename, T0.AddSeconds(10));
        Assert.True(detector.Observe(RansomwareSignalKind.Rename, T0.AddSeconds(10).AddMilliseconds(100)));
    }

    [Fact]
    public void Constructor_RejectsNonPositiveThreshold() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new RansomwareBurstDetector(threshold: 0));
}
