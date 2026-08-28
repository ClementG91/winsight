using WinSight.Ransomware;
using Xunit;

namespace WinSight.Ransomware.Tests;

/// <summary>
/// Formats whose content is compressed or encrypted by design, which high entropy therefore says
/// nothing about.
/// </summary>
/// <remarks>
/// The list held .docx, .xlsx and .pptx but not their macro-enabled and template siblings, which are
/// the same ZIP container. So saving a macro workbook - an autosave is enough - scored as
/// near-maximum entropy and counted toward a ransomware burst. That is the kind of false positive
/// that makes somebody uninstall a security tool, which the sampler's own documentation says in as
/// many words.
/// </remarks>
public sealed class CompressedByDesignTests
{
    [Theory]
    // The originals, still covered.
    [InlineData("Q4.docx")]
    [InlineData("Q4.xlsx")]
    [InlineData("Q4.pptx")]
    // The macro-enabled and template members of the same families.
    [InlineData("Budget.xlsm")]
    [InlineData("Report.docm")]
    [InlineData("Deck.pptm")]
    [InlineData("Model.xltx")]
    [InlineData("Letter.dotx")]
    [InlineData("Theme.potx")]
    // Other containers that are compressed by design.
    [InlineData("Diagram.vsdx")]
    [InlineData("Stencil.vssx")]
    [InlineData("Notes.one")]
    [InlineData("Archive.onepkg")]
    [InlineData("data.zst")]
    [InlineData("photo.avif")]
    [InlineData("track.opus")]
    public void ACompressedByDesignFormatIsNotScored(string path) =>
        Assert.False(RansomwareEntropySampler.ShouldSample(path));

    /// <summary>
    /// The formats ransomware actually rewrites must still be scored, or widening the exclusion list
    /// would have traded a false positive for a false negative.
    /// </summary>
    [Theory]
    [InlineData("notes.txt")]
    [InlineData("report.doc")]
    [InlineData("sheet.xls")]
    [InlineData("database.mdb")]
    [InlineData("photo.bmp")]
    [InlineData("Q4.xlsx.locked")]
    [InlineData("Q4.docx.encrypted")]
    [InlineData("payload")]
    public void AFormatRansomwareRewritesIsStillScored(string path) =>
        Assert.True(RansomwareEntropySampler.ShouldSample(path));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void ABlankPathIsNotScored(string? path) =>
        Assert.False(RansomwareEntropySampler.ShouldSample(path));
}
