using System.IO.Compression;
using System.Text;

using WinSight.Ransomware;
using Xunit;

namespace WinSight.Ransomware.Tests;

/// <summary>
/// A decoy must be the format its name claims, all the way in.
/// </summary>
/// <remarks>
/// <b>The residual tell.</b> Decoys are named <c>.xlsx</c> and <c>.docx</c>, and every one of them
/// received a workbook. Both are OOXML ZIPs, so the four-byte magic number matched and the check
/// this content generator was written for was satisfied - but a <c>.docx</c> whose
/// <c>[Content_Types].xml</c> declares a spreadsheet is a mismatch to anything that opens the
/// package rather than sniffing its first bytes. That is the same tell one level in, and a decoy
/// only convincing to the shallowest inspection has a shelf life.
/// </remarks>
public sealed class CanaryDocumentFormatTests
{
    private static string[] PartNames(byte[] package)
    {
        using var buffer = new MemoryStream(package);
        using var archive = new ZipArchive(buffer, ZipArchiveMode.Read);
        return [.. archive.Entries.Select(entry => entry.FullName)];
    }

    private static string Part(byte[] package, string name)
    {
        using var buffer = new MemoryStream(package);
        using var archive = new ZipArchive(buffer, ZipArchiveMode.Read);
        using var stream = archive.GetEntry(name)!.Open();
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    [Theory]
    [InlineData(".xlsx")]
    [InlineData(".docx")]
    public void EveryDecoyIsAnOoxmlPackage(string extension)
    {
        var package = CanaryDocument.For(extension);

        // PK\x03\x04 - what a family checking a magic number before encrypting is looking for.
        Assert.Equal(new byte[] { 0x50, 0x4B, 0x03, 0x04 }, package.Take(4));
        Assert.Contains("[Content_Types].xml", PartNames(package), StringComparer.Ordinal);
    }

    [Fact]
    public void ASpreadsheetNameGetsSpreadsheetContent()
    {
        var package = CanaryDocument.For(".xlsx");

        Assert.Contains("xl/workbook.xml", PartNames(package), StringComparer.Ordinal);
        Assert.Contains(
            "spreadsheetml", Part(package, "[Content_Types].xml"), StringComparison.Ordinal);
    }

    /// <summary>The case that was wrong: a document name receiving a workbook.</summary>
    [Fact]
    public void ADocumentNameGetsDocumentContent()
    {
        var package = CanaryDocument.For(".docx");

        Assert.Contains("word/document.xml", PartNames(package), StringComparer.Ordinal);
        Assert.DoesNotContain("xl/workbook.xml", PartNames(package), StringComparer.Ordinal);
        var contentTypes = Part(package, "[Content_Types].xml");
        Assert.Contains("wordprocessingml", contentTypes, StringComparison.Ordinal);
        Assert.DoesNotContain("spreadsheetml", contentTypes, StringComparison.Ordinal);
    }

    /// <summary>
    /// Nothing inside a decoy names the product. A trap that identifies itself is not a trap, and
    /// the content is the last place that could give it away.
    /// </summary>
    [Theory]
    [InlineData(".xlsx")]
    [InlineData(".docx")]
    public void NothingInsideADecoyNamesTheProduct(string extension)
    {
        var package = CanaryDocument.For(extension);
        var text = Encoding.UTF8.GetString(package);

        Assert.DoesNotContain("WinSight", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("canary", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("decoy", text, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The bytes do not vary between runs, so the entropy sampler's judgement of a decoy is stable
    /// and a decoy's content cannot become a signal of its own.
    /// </summary>
    [Theory]
    [InlineData(".xlsx")]
    [InlineData(".docx")]
    public void TheBytesAreDeterministic(string extension) =>
        Assert.Equal(CanaryDocument.For(extension), CanaryDocument.For(extension));

    /// <summary>
    /// An unrecognised extension still gets a valid package. A decoy that fails to plant protects
    /// nothing, so this defaults rather than throwing.
    /// </summary>
    [Fact]
    public void AnUnrecognisedExtensionStillGetsAPackage()
    {
        var package = CanaryDocument.For(".pptx");

        Assert.Equal(new byte[] { 0x50, 0x4B, 0x03, 0x04 }, package.Take(4));
    }

    /// <summary>
    /// End to end: the name pool and the content generator agree, so no planted decoy carries the
    /// wrong format. This is the assertion that would have caught the original mismatch.
    /// </summary>
    [Fact]
    public void EveryNameTheIdentityPoolProducesGetsMatchingContent()
    {
        var seed = new byte[32];
        var directory = @"C:\Users\me\Documents";

        for (var index = 0; index < CanaryIdentity.PerDirectory * 4; index++)
        {
            var name = CanaryIdentity.FileName(seed, directory, index);
            var extension = Path.GetExtension(name);
            var parts = PartNames(CanaryDocument.For(extension));

            var expected = extension.Equals(".docx", StringComparison.OrdinalIgnoreCase)
                ? "word/document.xml"
                : "xl/workbook.xml";
            Assert.Contains(expected, parts, StringComparer.Ordinal);
        }
    }

    /// <summary>
    /// A decoy rewritten with exactly its own bytes has not been touched in any sense that matters.
    /// </summary>
    /// <remarks>
    /// The decoy directories follow the OneDrive redirection deliberately and LastWrite is in the
    /// notify filter, so a placeholder hydrating or dehydrating - or any synchronisation client
    /// round-tripping the file - raised the one signal this product presents as unambiguous.
    /// </remarks>
    [Fact]
    public void ADecoyRewrittenWithItsOwnBytesIsIntact()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"winsight-intact-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var manifest = Path.Combine(directory, "manifest.txt");
        var manager = new CanaryManager(seed: new byte[32], manifestPath: manifest);
        try
        {
            var decoy = manager.Plant([directory])[0];

            Assert.True(manager.ContentIsIntact(decoy));

            // What a sync client does: write the same bytes back.
            File.WriteAllBytes(decoy, File.ReadAllBytes(decoy));
            Assert.True(manager.ContentIsIntact(decoy));

            // What encryption does.
            File.WriteAllBytes(decoy, [0xDE, 0xAD, 0xBE, 0xEF]);
            Assert.False(manager.ContentIsIntact(decoy));
        }
        finally
        {
            manager.Remove();
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// A decoy that cannot be read counts as modified. It is the one place in this codebase where
    /// "I could not look" must not resolve to silence: an unreadable decoy is exactly what
    /// encryption in progress looks like.
    /// </summary>
    [Fact]
    public void AnUnreadableDecoyIsNotReportedAsIntact()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"winsight-gone-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var manifest = Path.Combine(directory, "manifest.txt");
        var manager = new CanaryManager(seed: new byte[32], manifestPath: manifest);
        try
        {
            var decoy = manager.Plant([directory])[0];
            File.Delete(decoy);

            Assert.False(manager.ContentIsIntact(decoy));
        }
        finally
        {
            manager.Remove();
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>A path that is not a decoy is never "intact"; it is not this manager's file.</summary>
    [Fact]
    public void APathThatIsNotADecoyIsNotIntact() =>
        Assert.False(new CanaryManager(seed: new byte[32]).ContentIsIntact(@"C:\Windows\notepad.exe"));
}
