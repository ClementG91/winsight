using System.IO.Compression;
using System.Text;

namespace WinSight.Ransomware;

/// <summary>
/// Produces decoy file content that is genuinely the format its extension claims.
/// </summary>
/// <remarks>
/// <b>Why the content mattered.</b> The previous decoys were named <c>.xlsx</c> and contained one
/// line of plain ASCII beginning "WinSight ransomware canary". Anything that read four bytes could
/// tell: a real OOXML file starts <c>PK\x03\x04</c>, and the sentence named the product outright. A
/// trap that identifies itself in its first line is not a trap, and the mismatch alone was enough —
/// several families check a magic number before encrypting, precisely to skip files that are not
/// what they claim.
///
/// <b>What is produced instead.</b> The minimum set of parts that makes a document the Office
/// application opens: the content types, the package relationships, and the body. It stores
/// deterministically (fixed timestamps, no compression) so a decoy's bytes do not vary between runs
/// and the entropy sampler's judgement of it is stable.
///
/// <b>Both formats, because both names are used.</b> Decoys are named <c>.xlsx</c> and <c>.docx</c>,
/// and every one of them used to receive a workbook. Both are OOXML ZIPs, so the four-byte magic
/// number matched and the check that motivated this class was satisfied - but a <c>.docx</c> whose
/// <c>[Content_Types].xml</c> declares a spreadsheet is a mismatch to anything that opens the
/// package rather than sniffing its first bytes, which is the same tell one level in. A decoy that
/// is only convincing to the shallowest inspection is a decoy with a shelf life.
///
/// <b>It stays cheap.</b> A few kilobytes per decoy, written once when protection is turned on.
/// </remarks>
public static class CanaryDocument
{
    private static readonly DateTimeOffset FixedTimestamp =
        new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// The decoy content for a file with this extension, as bytes.
    /// </summary>
    /// <remarks>
    /// An unrecognised extension gets a workbook, which is what every decoy used to get. The name
    /// pool decides the extensions, so this is unreachable today; it is a default rather than a
    /// throw because a decoy that fails to plant protects nothing, and an OOXML package under an
    /// unexpected name is still a better decoy than no decoy.
    /// </remarks>
    public static byte[] For(string extension) =>
        extension.Equals(".docx", StringComparison.OrdinalIgnoreCase) ? Document() : Workbook();

    /// <summary>An OOXML workbook, as bytes.</summary>
    public static byte[] Workbook()
    {
        using var buffer = new MemoryStream();
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            // [Content_Types].xml must be the first part; Excel rejects a package without it.
            Write(archive, "[Content_Types].xml",
                """
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
                  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
                  <Default Extension="xml" ContentType="application/xml"/>
                  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
                  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
                </Types>
                """);

            Write(archive, "_rels/.rels",
                """
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
                  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
                </Relationships>
                """);

            Write(archive, "xl/workbook.xml",
                """
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
                          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
                  <sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>
                </workbook>
                """);

            Write(archive, "xl/_rels/workbook.xml.rels",
                """
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
                  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
                </Relationships>
                """);

            // Ordinary-looking cell content. Nothing here names WinSight: an operator who opens a
            // decoy sees a spreadsheet, and so does anything else that looks inside it.
            Write(archive, "xl/worksheets/sheet1.xml",
                """
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
                  <sheetData>
                    <row r="1"><c r="A1" t="inlineStr"><is><t>Period</t></is></c><c r="B1" t="inlineStr"><is><t>Amount</t></is></c></row>
                    <row r="2"><c r="A2" t="inlineStr"><is><t>Q1</t></is></c><c r="B2"><v>18400</v></c></row>
                    <row r="3"><c r="A3" t="inlineStr"><is><t>Q2</t></is></c><c r="B3"><v>21750</v></c></row>
                    <row r="4"><c r="A4" t="inlineStr"><is><t>Q3</t></is></c><c r="B4"><v>19980</v></c></row>
                    <row r="5"><c r="A5" t="inlineStr"><is><t>Q4</t></is></c><c r="B5"><v>24310</v></c></row>
                  </sheetData>
                </worksheet>
                """);
        }
        return buffer.ToArray();
    }

    /// <summary>An OOXML wordprocessing document, as bytes.</summary>
    public static byte[] Document()
    {
        using var buffer = new MemoryStream();
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            // Same three-part minimum as the workbook, declaring wordprocessing rather than
            // spreadsheet content - which is the whole point of this method existing.
            Write(archive, "[Content_Types].xml",
                """
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
                  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
                  <Default Extension="xml" ContentType="application/xml"/>
                  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
                </Types>
                """);

            Write(archive, "_rels/.rels",
                """
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
                  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
                </Relationships>
                """);

            // Ordinary-looking prose. Nothing here names WinSight: an operator who opens a decoy
            // sees a document, and so does anything else that looks inside it.
            Write(archive, "word/document.xml",
                """
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
                  <w:body>
                    <w:p><w:r><w:t>Quarterly summary</w:t></w:r></w:p>
                    <w:p><w:r><w:t>Prepared for the finance review. Figures are provisional and</w:t></w:r></w:p>
                    <w:p><w:r><w:t>subject to confirmation before the year-end close.</w:t></w:r></w:p>
                    <w:p><w:r><w:t>Distribution: internal only.</w:t></w:r></w:p>
                  </w:body>
                </w:document>
                """);
        }
        return buffer.ToArray();
    }

    private static void Write(ZipArchive archive, string name, string content)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
        entry.LastWriteTime = FixedTimestamp;
        using var stream = entry.Open();
        var bytes = Encoding.UTF8.GetBytes(content);
        stream.Write(bytes, 0, bytes.Length);
    }
}
