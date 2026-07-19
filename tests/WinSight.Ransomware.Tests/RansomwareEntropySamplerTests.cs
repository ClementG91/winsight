using WinSight.Ransomware;

using Xunit;

namespace WinSight.Ransomware.Tests;

public sealed class RansomwareEntropySamplerTests
{
    [Theory]
    // Compressed or encrypted by design: high entropy says nothing, so never score them. .docx and
    // friends matter most — they are ZIP containers, and flagging a saved Word file would be the
    // false positive that gets a security tool uninstalled.
    [InlineData("photo.jpg")]
    [InlineData("archive.zip")]
    [InlineData("report.docx")]
    [InlineData("book.xlsx")]
    [InlineData("movie.mp4")]
    [InlineData("setup.exe")]
    [InlineData("lib.dll")]
    [InlineData("manual.pdf")]
    public void ShouldSample_FormatsCompressedByDesign_AreSkipped(string name) =>
        Assert.False(RansomwareEntropySampler.ShouldSample(name));

    [Theory]
    [InlineData("notes.txt")]
    [InlineData("data.csv")]
    [InlineData("old-report.doc")]
    [InlineData("payroll.xls")]
    // Ransomware's own extensions are exactly what we DO want to score.
    [InlineData("payroll.xlsx.locked")]
    [InlineData("notes.txt.encrypted")]
    [InlineData("no-extension")]
    public void ShouldSample_OrdinaryOrRansomExtensions_AreScored(string name) =>
        Assert.True(RansomwareEntropySampler.ShouldSample(name));

    [Fact]
    public void ShouldSample_BlankPath_IsFalse() =>
        Assert.False(RansomwareEntropySampler.ShouldSample("   "));

    [Fact]
    public void LooksEncrypted_HighEntropyContentInAScorableFile_IsTrue()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wsg-ent-{Guid.NewGuid():N}.locked");
        try
        {
            var data = new byte[2048];
            for (var i = 0; i < data.Length; i++)
            {
                data[i] = (byte)(i % 256); // uniform over all byte values => entropy 8.0
            }
            File.WriteAllBytes(path, data);

            Assert.True(RansomwareEntropySampler.LooksEncrypted(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void LooksEncrypted_PlainTextFile_IsFalse()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wsg-ent-{Guid.NewGuid():N}.txt");
        try
        {
            File.WriteAllText(path, string.Concat(Enumerable.Repeat("the quick brown fox. ", 100)));
            Assert.False(RansomwareEntropySampler.LooksEncrypted(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void LooksEncrypted_HighEntropyButCompressedByDesign_IsFalse()
    {
        // Identical bytes to the .locked case, but named .zip: the extension gate must win, because
        // a real .zip looks exactly like this and is entirely legitimate.
        var path = Path.Combine(Path.GetTempPath(), $"wsg-ent-{Guid.NewGuid():N}.zip");
        try
        {
            var data = new byte[2048];
            for (var i = 0; i < data.Length; i++)
            {
                data[i] = (byte)(i % 256);
            }
            File.WriteAllBytes(path, data);

            Assert.False(RansomwareEntropySampler.LooksEncrypted(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void LooksEncrypted_ADirectory_IsFalse_NotAnAttemptToReadIt()
    {
        // A Created event can name a directory. Opening it would throw; the guard must catch it
        // cheaply, alongside the reparse-point check that stops us following links off the machine.
        var dir = Path.Combine(Path.GetTempPath(), $"wsg-dir-{Guid.NewGuid():N}.locked");
        Directory.CreateDirectory(dir);
        try
        {
            Assert.False(RansomwareEntropySampler.LooksEncrypted(dir));
        }
        finally
        {
            Directory.Delete(dir);
        }
    }

    [Fact]
    public void LooksEncrypted_MissingFile_IsFalseNotAnException() =>
        Assert.False(RansomwareEntropySampler.LooksEncrypted(
            Path.Combine(Path.GetTempPath(), $"gone-{Guid.NewGuid():N}.txt")));
}

public sealed class RansomwareClassifierEntropyTests
{
    [Theory]
    [InlineData(WatcherChangeTypes.Created)]
    [InlineData(WatcherChangeTypes.Changed)]
    public void Classify_CreateOrChange_WithEncryptedLookingContent_IsAHighEntropyWrite(
        WatcherChangeTypes changeType) =>
        Assert.Equal(
            RansomwareSignalKind.HighEntropyWrite,
            RansomwareSignalClassifier.Classify(changeType, isCanary: false, looksEncrypted: true));

    [Theory]
    [InlineData(WatcherChangeTypes.Created)]
    [InlineData(WatcherChangeTypes.Changed)]
    public void Classify_CreateOrChange_WithOrdinaryContent_IsStillNotASignal(
        WatcherChangeTypes changeType) =>
        Assert.Null(RansomwareSignalClassifier.Classify(changeType, isCanary: false, looksEncrypted: false));

    [Fact]
    public void Classify_ACanaryWins_EvenWhenContentLooksEncrypted() =>
        Assert.Equal(
            RansomwareSignalKind.CanaryTouched,
            RansomwareSignalClassifier.Classify(
                WatcherChangeTypes.Changed, isCanary: true, looksEncrypted: true));
}
