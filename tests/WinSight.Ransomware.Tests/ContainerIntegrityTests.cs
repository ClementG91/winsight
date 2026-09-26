using WinSight.Ransomware;

using Xunit;

namespace WinSight.Ransomware.Tests;

/// <summary>
/// Proves the two independent gates used for compressed/container formats: a healthy signature is
/// never suspicious regardless of entropy, while a missing signature is not suspicious unless the
/// bounded sample is also large enough and genuinely high entropy.
/// </summary>
public sealed class ContainerIntegrityTests
{
    public static TheoryData<string, byte[]> HealthyContainers => new()
    {
        { "report.docx", [0x50, 0x4B, 0x03, 0x04] },
        { "empty.zip", [0x50, 0x4B, 0x05, 0x06] },
        { "split.zip", [0x50, 0x4B, 0x07, 0x08] },
        { "archive.7z", [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] },
        { "archive.rar", [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00] },
        { "archive.gz", [0x1F, 0x8B] },
        { "archive.bz2", "BZh"u8.ToArray() },
        { "archive.xz", [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] },
        { "archive.zst", [0x28, 0xB5, 0x2F, 0xFD] },
        { "archive.lz4", [0x04, 0x22, 0x4D, 0x18] },
        { "package.cab", "MSCF"u8.ToArray() },
        { "package.msi", [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] },
        { "photo.jpg", [0xFF, 0xD8, 0xFF] },
        { "photo.png", [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] },
        { "animation.gif", "GIF89a"u8.ToArray() },
        { "photo.tiff", [0x49, 0x49, 0x2A, 0x00] },
        { "audio.flac", "fLaC"u8.ToArray() },
        { "audio.opus", "OggS"u8.ToArray() },
        { "program.exe", "MZ"u8.ToArray() },
        { "module.wasm", [0x00, 0x61, 0x73, 0x6D] },
        { "design.psd", "8BPS"u8.ToArray() },
        { "disk.vhdx", "vhdxfile"u8.ToArray() },
        { "objects.pack", "PACK"u8.ToArray() },
        { "notes.one", [0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D,
                          0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3] },
    };

    [Theory]
    [MemberData(nameof(HealthyContainers))]
    public void ValidContainerSignatureWinsOverHighEntropy(string path, byte[] signature)
    {
        var sample = HighEntropySample();
        signature.CopyTo(sample, 0);

        Assert.False(RansomwareEntropySampler.LooksEncryptedSample(path, sample));
    }

    [Fact]
    public void PdfHeaderMayFollowAStandardsPermittedPreamble()
    {
        var sample = HighEntropySample();
        "%PDF-1.7"u8.CopyTo(sample.AsSpan(512));

        Assert.False(RansomwareEntropySampler.LooksEncryptedSample("manual.pdf", sample));
    }

    [Fact]
    public void PasswordProtectedOfficeCompoundFileIsAHealthyAlternateEnvelope()
    {
        // Office stores an encrypted OOXML package inside an OLE Compound File. It is legitimately
        // high entropy and keeps its .docx/.xlsx/.pptx extension, so ZIP-only validation would turn
        // the exact act of password-protecting a document into a ransomware signal.
        var sample = HighEntropySample();
        byte[] compoundFile = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        compoundFile.CopyTo(sample, 0);

        Assert.False(RansomwareEntropySampler.LooksEncryptedSample("protected.docx", sample));
        Assert.False(RansomwareEntropySampler.LooksEncryptedSample("protected.xlsx", sample));
        Assert.False(RansomwareEntropySampler.LooksEncryptedSample("protected.pptx", sample));
    }

    [Fact]
    public void ZipPreambleIsAcceptedWithinABoundedWindow()
    {
        var sample = HighEntropySample();
        byte[] localHeader = [0x50, 0x4B, 0x03, 0x04];
        localHeader.CopyTo(sample, 512);

        Assert.False(RansomwareEntropySampler.LooksEncryptedSample("archive.zip", sample));
    }

    [Fact]
    public void IsoBaseMediaSignatureIsCheckedAtItsDefinedOffset()
    {
        var sample = HighEntropySample();
        "ftyp"u8.CopyTo(sample.AsSpan(4));

        Assert.False(RansomwareEntropySampler.LooksEncryptedSample("video.mp4", sample));
    }

    [Fact]
    public void RiffContainerRequiresTheExpectedForm()
    {
        var webp = HighEntropySample();
        "RIFF"u8.CopyTo(webp);
        "WEBP"u8.CopyTo(webp.AsSpan(8));
        var avi = HighEntropySample();
        "RIFF"u8.CopyTo(avi);
        "AVI "u8.CopyTo(avi.AsSpan(8));

        Assert.False(RansomwareEntropySampler.LooksEncryptedSample("photo.webp", webp));
        Assert.False(RansomwareEntropySampler.LooksEncryptedSample("movie.avi", avi));
        Assert.True(RansomwareEntropySampler.LooksEncryptedSample("movie.avi", webp));
    }

    [Theory]
    [InlineData("report.docx")]
    [InlineData("archive.zip")]
    [InlineData("archive.7z")]
    [InlineData("archive.rar")]
    [InlineData("archive.gz")]
    [InlineData("archive.zst")]
    [InlineData("package.cab")]
    [InlineData("package.msi")]
    [InlineData("photo.jpg")]
    [InlineData("photo.png")]
    [InlineData("photo.tif")]
    [InlineData("icon.ico")]
    [InlineData("manual.pdf")]
    [InlineData("audio.mp3")]
    [InlineData("video.mp4")]
    [InlineData("video.m4v")]
    [InlineData("movie.mkv")]
    [InlineData("audio.opus")]
    [InlineData("video.wmv")]
    [InlineData("program.exe")]
    [InlineData("module.wasm")]
    [InlineData("design.psd")]
    [InlineData("disk.vhdx")]
    [InlineData("notes.one")]
    public void DestroyedSignatureAndHighEntropyDetectsInPlaceEncryption(string path) =>
        Assert.True(RansomwareEntropySampler.LooksEncryptedSample(path, HighEntropySample()));

    [Fact]
    public void DestroyedSignatureWithoutHighEntropyIsNotEnough()
    {
        var ordinaryRewriteInProgress = Enumerable.Repeat((byte)'A', 2048).ToArray();

        Assert.False(RansomwareEntropySampler.LooksEncryptedSample(
            "report.docx", ordinaryRewriteInProgress));
    }

    [Fact]
    public void DestroyedSignatureWithATinySampleIsNotEnough()
    {
        var tooSmallToJudge = HighEntropySample(ShannonEntropy.MinimumSampleBytes - 1);

        Assert.False(RansomwareEntropySampler.LooksEncryptedSample("report.docx", tooSmallToJudge));
    }

    [Theory]
    [InlineData("stream.br")]
    [InlineData("image.iso")]
    [InlineData("backup.bak")]
    public void CompressedFormatsWithoutAReliablePrefixRemainIgnored(string path) =>
        Assert.False(RansomwareEntropySampler.LooksEncryptedSample(path, HighEntropySample()));

    [Fact]
    public void GitObjectStoreExclusionStillWins()
    {
        Assert.False(RansomwareEntropySampler.LooksEncryptedSample(
            @"C:\work\repo\.git\objects\report.docx", HighEntropySample()));
    }

    private static byte[] HighEntropySample(int length = 2048)
    {
        var sample = new byte[length];
        for (var i = 0; i < sample.Length; i++)
        {
            sample[i] = (byte)i;
        }
        return sample;
    }
}
