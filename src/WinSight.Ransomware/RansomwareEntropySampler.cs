using WinSight.Core;

namespace WinSight.Ransomware;

/// <summary>
/// Decides whether a freshly written file "looks encrypted", by inspecting a bounded prefix. Plain
/// formats are scored with <see cref="ShannonEntropy"/>. Common compressed/container formats are
/// scored only when their mandatory file signature has disappeared, because high entropy by itself
/// is normal for those formats.
/// </summary>
/// <remarks>
/// <b>Compressed formats are never classified from entropy alone.</b> A .zip, .jpg, .mp4 — and
/// crucially .docx/.xlsx/.pptx, which are ZIP containers — are legitimately near-maximum entropy.
/// A supported container is therefore suspicious only when both its expected signature is absent
/// and the remaining bytes look encrypted. This covers the common ransomware pattern that encrypts
/// a file in place without changing its extension, while ordinary saves take the cheap signature
/// fast path. Formats without a reliable leading signature remain excluded rather than guessed.
///
/// <b>Reads are bounded.</b> Only <see cref="MaxSampleBytes"/> are read, with sharing flags that do
/// not block the writer, and any I/O trouble (locked, gone, denied) yields false rather than an
/// exception — a detector must never become the thing that breaks the machine.
/// </remarks>
public static class RansomwareEntropySampler
{
    /// <summary>How much of a file is read to score it. A prefix is enough and bounds the cost.</summary>
    public const int MaxSampleBytes = 4096;

    // Formats whose content is compressed or encrypted by design, so entropy alone says nothing.
    private static readonly HashSet<string> CompressedByDesign = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".tgz", ".cab", ".iso", ".msi",
        ".jpg", ".jpeg", ".jfif", ".png", ".gif", ".webp", ".heic", ".tif", ".tiff", ".ico",
        ".mp3", ".mp4", ".m4a", ".m4v", ".3gp", ".3g2", ".mkv", ".avi", ".mov", ".webm",
        ".flac", ".ogg", ".oga", ".wmv", ".asf", ".mpg", ".mpeg",
        ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub",
        // The macro-enabled and newer Office members are ZIP containers exactly like their plain
        // counterparts, and leaving them out flagged an ordinary autosave of a macro workbook as
        // ransomware. .one and .vsdx are compressed by design too.
        ".xlsm", ".xlsb", ".xltx", ".xltm", ".xlam",
        ".docm", ".dotx", ".dotm",
        ".pptm", ".potx", ".potm", ".ppsx", ".ppsm", ".ppam", ".sldx", ".sldm", ".thmx",
        ".vsdx", ".vsdm", ".vssx", ".vssm", ".vstx", ".vstm", ".one", ".onepkg",
        ".ott", ".ots", ".otp", ".odg", ".xps", ".oxps", ".appx", ".appxbundle", ".msix", ".msixbundle",
        // Modern archive and media containers that behave the same way.
        ".zst", ".lz4", ".br", ".opus", ".aac", ".wma", ".avif", ".jxl",
        ".exe", ".dll", ".sys", ".apk", ".jar", ".nupkg", ".whl",
        // Measured against ordinary developer and creative work on a real machine, each of which
        // produced high-entropy writes in bulk under a watched folder:
        //   .pack   git packfiles, written by every clone and gc
        //   .wasm   compiled modules, shipped inside node_modules
        //   .psd    Photoshop documents, compressed by design
        //   .vhdx   virtual disks, whose contents are whatever the guest wrote
        //   .bak    backups, which are usually a compressed copy of something
        //   .vsix   Visual Studio extensions, which are ZIP containers
        ".pack", ".wasm", ".psd", ".vhdx", ".bak", ".vsix",
    };

    // Only formats with a stable, cheaply testable prefix belong here. A format that has no magic
    // number (Brotli), admits too many unrelated byte layouts, or needs a deep parser stays in
    // CompressedByDesign and is ignored. That asymmetry is deliberate: a false negative is recorded
    // as residual coverage, while a noisy detector eventually gets disabled by its operator.
    private static readonly Dictionary<string, ContainerKind> ContainerByExtension =
        new(StringComparer.OrdinalIgnoreCase)
        {
            [".zip"] = ContainerKind.Zip,
            [".docx"] = ContainerKind.OfficeOpenXml,
            [".xlsx"] = ContainerKind.OfficeOpenXml,
            [".pptx"] = ContainerKind.OfficeOpenXml,
            [".odt"] = ContainerKind.Zip,
            [".ods"] = ContainerKind.Zip,
            [".odp"] = ContainerKind.Zip,
            [".epub"] = ContainerKind.Zip,
            [".ott"] = ContainerKind.Zip,
            [".ots"] = ContainerKind.Zip,
            [".otp"] = ContainerKind.Zip,
            [".odg"] = ContainerKind.Zip,
            [".xlsm"] = ContainerKind.OfficeOpenXml,
            [".xlsb"] = ContainerKind.OfficeOpenXml,
            [".xltx"] = ContainerKind.OfficeOpenXml,
            [".xltm"] = ContainerKind.OfficeOpenXml,
            [".xlam"] = ContainerKind.OfficeOpenXml,
            [".docm"] = ContainerKind.OfficeOpenXml,
            [".dotx"] = ContainerKind.OfficeOpenXml,
            [".dotm"] = ContainerKind.OfficeOpenXml,
            [".pptm"] = ContainerKind.OfficeOpenXml,
            [".potx"] = ContainerKind.OfficeOpenXml,
            [".potm"] = ContainerKind.OfficeOpenXml,
            [".ppsx"] = ContainerKind.OfficeOpenXml,
            [".ppsm"] = ContainerKind.OfficeOpenXml,
            [".ppam"] = ContainerKind.OfficeOpenXml,
            [".sldx"] = ContainerKind.OfficeOpenXml,
            [".sldm"] = ContainerKind.OfficeOpenXml,
            [".thmx"] = ContainerKind.OfficeOpenXml,
            [".vsdx"] = ContainerKind.OfficeOpenXml,
            [".vsdm"] = ContainerKind.OfficeOpenXml,
            [".vssx"] = ContainerKind.OfficeOpenXml,
            [".vssm"] = ContainerKind.OfficeOpenXml,
            [".vstx"] = ContainerKind.OfficeOpenXml,
            [".vstm"] = ContainerKind.OfficeOpenXml,
            [".xps"] = ContainerKind.Zip,
            [".oxps"] = ContainerKind.Zip,
            [".apk"] = ContainerKind.Zip,
            [".jar"] = ContainerKind.Zip,
            [".nupkg"] = ContainerKind.Zip,
            [".whl"] = ContainerKind.Zip,
            [".vsix"] = ContainerKind.Zip,
            [".appx"] = ContainerKind.Zip,
            [".appxbundle"] = ContainerKind.Zip,
            [".msix"] = ContainerKind.Zip,
            [".msixbundle"] = ContainerKind.Zip,
            [".7z"] = ContainerKind.SevenZip,
            [".rar"] = ContainerKind.Rar,
            [".gz"] = ContainerKind.GZip,
            [".tgz"] = ContainerKind.GZip,
            [".bz2"] = ContainerKind.BZip2,
            [".xz"] = ContainerKind.Xz,
            [".zst"] = ContainerKind.Zstandard,
            [".lz4"] = ContainerKind.Lz4,
            [".cab"] = ContainerKind.Cabinet,
            [".onepkg"] = ContainerKind.Cabinet,
            [".msi"] = ContainerKind.CompoundFile,
            [".jpg"] = ContainerKind.Jpeg,
            [".jpeg"] = ContainerKind.Jpeg,
            [".jfif"] = ContainerKind.Jpeg,
            [".png"] = ContainerKind.Png,
            [".gif"] = ContainerKind.Gif,
            [".webp"] = ContainerKind.WebP,
            [".tif"] = ContainerKind.Tiff,
            [".tiff"] = ContainerKind.Tiff,
            [".ico"] = ContainerKind.Icon,
            [".pdf"] = ContainerKind.Pdf,
            [".mp3"] = ContainerKind.Mp3,
            [".mp4"] = ContainerKind.IsoBaseMedia,
            [".m4a"] = ContainerKind.IsoBaseMedia,
            [".m4v"] = ContainerKind.IsoBaseMedia,
            [".3gp"] = ContainerKind.IsoBaseMedia,
            [".3g2"] = ContainerKind.IsoBaseMedia,
            [".mov"] = ContainerKind.IsoBaseMedia,
            [".heic"] = ContainerKind.IsoBaseMedia,
            [".avif"] = ContainerKind.IsoBaseMedia,
            [".mkv"] = ContainerKind.Ebml,
            [".webm"] = ContainerKind.Ebml,
            [".avi"] = ContainerKind.Avi,
            [".flac"] = ContainerKind.Flac,
            [".opus"] = ContainerKind.Ogg,
            [".ogg"] = ContainerKind.Ogg,
            [".oga"] = ContainerKind.Ogg,
            [".aac"] = ContainerKind.Aac,
            [".wma"] = ContainerKind.Asf,
            [".wmv"] = ContainerKind.Asf,
            [".asf"] = ContainerKind.Asf,
            [".jxl"] = ContainerKind.JpegXl,
            [".exe"] = ContainerKind.PortableExecutable,
            [".dll"] = ContainerKind.PortableExecutable,
            [".sys"] = ContainerKind.PortableExecutable,
            [".wasm"] = ContainerKind.WebAssembly,
            [".psd"] = ContainerKind.Photoshop,
            [".vhdx"] = ContainerKind.Vhdx,
            [".pack"] = ContainerKind.GitPack,
            [".one"] = ContainerKind.OneNote,
        };

    private static readonly byte[] SevenZipSignature = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
    private static readonly byte[] Rar4Signature = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];
    private static readonly byte[] Rar5Signature = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];
    private static readonly byte[] GZipSignature = [0x1F, 0x8B];
    private static readonly byte[] XzSignature = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
    private static readonly byte[] ZstandardSignature = [0x28, 0xB5, 0x2F, 0xFD];
    private static readonly byte[] Lz4Signature = [0x04, 0x22, 0x4D, 0x18];
    private static readonly byte[] JpegSignature = [0xFF, 0xD8, 0xFF];
    private static readonly byte[] PngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    private static readonly byte[] CompoundFileSignature = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    private static readonly byte[] EbmlSignature = [0x1A, 0x45, 0xDF, 0xA3];
    private static readonly byte[] AsfSignature =
        [0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C];
    private static readonly byte[] JpegXlContainerSignature =
        [0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A];
    private static readonly byte[] JpegXlCodestreamSignature = [0xFF, 0x0A];
    private static readonly byte[] WebAssemblySignature = [0x00, 0x61, 0x73, 0x6D];
    private static readonly byte[] OneNoteSignature =
        [0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D, 0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3];

    /// <summary>
    /// Pure: whether this path is worth scoring at all. False for formats that are compressed by
    /// design (see remarks) and for a blank path.
    /// </summary>
    public static bool ShouldSample(string? path)
    {
        return TryGetInspectionKind(path, out var container) && container == ContainerKind.None;
    }

    private static bool TryGetInspectionKind(string? path, out ContainerKind container)
    {
        container = ContainerKind.None;
        if (string.IsNullOrWhiteSpace(path) || IsInsideObjectStore(path))
        {
            return false;
        }

        // The alternate lookups accept the extension span directly. This avoids allocating one
        // short string for every filesystem event in the worker's hot path.
        var extension = Path.GetExtension(path.AsSpan());

        if (ContainerByExtension
            .GetAlternateLookup<ReadOnlySpan<char>>()
            .TryGetValue(extension, out container))
        {
            return true;
        }

        // A content-addressed object store is excluded by its location, not by its extension.
        //
        // The obvious move was to stop scoring files with no extension - git loose objects and pack
        // files are exactly that, and a `git clone` under Documents produced the same signal as mass
        // encryption. But this codebase already decided the other way, and the reasoning holds:
        // ransomware writes extensionless output too, and widening the exclusion by extension would
        // trade a broad false positive for a real false negative.
        //
        // Naming the actual cause costs nothing on either side. Files inside a .git directory are
        // high-entropy by construction and are written in bulk by ordinary work; a document in the
        // working tree beside it is still scored, and encrypting a repository still produces the
        // renames and deletes the same detector counts.
        return !CompressedByDesign
            .GetAlternateLookup<ReadOnlySpan<char>>()
            .Contains(extension);
    }

    /// <summary>
    /// Whether the path sits inside a content-addressed object store whose contents are
    /// high-entropy by construction.
    /// </summary>
    /// <remarks>
    /// Matched as a path segment, so a document called <c>.gitignore</c> or a folder named
    /// <c>github</c> is not swept up with it.
    /// </remarks>
    private static bool IsInsideObjectStore(string path)
    {
        const string git = ".git";
        var span = path.AsSpan();
        var index = span.IndexOf(git, StringComparison.OrdinalIgnoreCase);
        while (index >= 0)
        {
            var startsSegment = index == 0 || span[index - 1] is '\\' or '/';
            var after = index + git.Length;
            var endsSegment = after < span.Length && span[after] is '\\' or '/';
            if (startsSegment && endsSegment)
            {
                return true;
            }
            var next = span[(index + git.Length)..].IndexOf(git, StringComparison.OrdinalIgnoreCase);
            index = next < 0 ? -1 : index + git.Length + next;
        }
        return false;
    }

    /// <summary>
    /// Best-effort: reads a bounded prefix of <paramref name="path"/> and reports whether it looks
    /// encrypted. Supported containers additionally require a broken format signature. Returns
    /// false for unsupported compressed formats and for any I/O trouble.
    /// </summary>
    public static bool LooksEncrypted(string? path)
    {
        if (!TryGetInspectionKind(path, out var container))
        {
            return false;
        }

        try
        {
            // Atomically refuse every reparse component while still sharing write/delete with the
            // active writer. A path pre-check followed by FileStream.Open could be redirected in the
            // gap; the native lease parses once with OBJ_DONT_REPARSE and reopens that exact object.
            using var lease = AutomaticFileAccess.TryAcquireSharedRead(path);
            if (lease is null || lease.IsDirectory)
            {
                return false;
            }
            using var stream = lease.OpenRead();

            Span<byte> buffer = stackalloc byte[MaxSampleBytes];
            var read = stream.ReadAtLeast(buffer, MaxSampleBytes, throwOnEndOfStream: false);
            return LooksEncryptedSample(container, buffer[..read]);
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or NotSupportedException
                                     or ArgumentException)
        {
            return false;
        }
    }

    /// <summary>
    /// Pure content decision used by tests and validation probes. It intentionally applies the same
    /// path exclusions as <see cref="LooksEncrypted(string?)"/> without touching the filesystem.
    /// </summary>
    internal static bool LooksEncryptedSample(string? path, ReadOnlySpan<byte> sample) =>
        TryGetInspectionKind(path, out var container) && LooksEncryptedSample(container, sample);

    private static bool LooksEncryptedSample(ContainerKind container, ReadOnlySpan<byte> sample)
    {
        // Check the signature first. This is both the false-positive guard and the ordinary hot
        // path: a healthy compressed file returns after a handful of byte comparisons without
        // building the 256-bin entropy histogram.
        if (container != ContainerKind.None && MatchesExpectedSignature(container, sample))
        {
            return false;
        }

        return ShannonEntropy.LooksEncrypted(sample);
    }

    private static bool MatchesExpectedSignature(ContainerKind kind, ReadOnlySpan<byte> sample) =>
        kind switch
        {
            ContainerKind.Zip => IsZip(sample),
            ContainerKind.OfficeOpenXml => IsZip(sample) || sample.StartsWith(CompoundFileSignature),
            ContainerKind.SevenZip => sample.StartsWith(SevenZipSignature),
            ContainerKind.Rar => IsRar(sample),
            ContainerKind.GZip => sample.StartsWith(GZipSignature),
            ContainerKind.BZip2 => sample.StartsWith("BZh"u8),
            ContainerKind.Xz => sample.StartsWith(XzSignature),
            ContainerKind.Zstandard => IsZstandard(sample),
            ContainerKind.Lz4 => IsLz4(sample),
            ContainerKind.Cabinet => sample.StartsWith("MSCF"u8),
            ContainerKind.CompoundFile => sample.StartsWith(CompoundFileSignature),
            ContainerKind.Jpeg => sample.StartsWith(JpegSignature),
            ContainerKind.Png => sample.StartsWith(PngSignature),
            ContainerKind.Gif => sample.StartsWith("GIF87a"u8) || sample.StartsWith("GIF89a"u8),
            ContainerKind.WebP => IsRiff(sample, "WEBP"u8),
            ContainerKind.Tiff => sample.StartsWith("II*\0"u8) || sample.StartsWith("MM\0*"u8),
            ContainerKind.Icon => sample.StartsWith("\0\0\x01\0"u8),
            ContainerKind.Pdf => sample[..Math.Min(sample.Length, 1024)].IndexOf("%PDF-"u8) >= 0,
            ContainerKind.Mp3 => sample.StartsWith("ID3"u8) || HasMpegAudioSync(sample),
            ContainerKind.IsoBaseMedia => sample.Length >= 12 && sample[4..8].SequenceEqual("ftyp"u8),
            ContainerKind.Ebml => sample.StartsWith(EbmlSignature),
            ContainerKind.Avi => IsRiff(sample, "AVI "u8),
            ContainerKind.Flac => sample.StartsWith("fLaC"u8),
            ContainerKind.Ogg => sample.StartsWith("OggS"u8),
            ContainerKind.Aac => sample.StartsWith("ADIF"u8) || HasAdtsSync(sample),
            ContainerKind.Asf => sample.StartsWith(AsfSignature),
            ContainerKind.JpegXl => IsJpegXl(sample),
            ContainerKind.PortableExecutable => sample.StartsWith("MZ"u8),
            ContainerKind.WebAssembly => sample.StartsWith(WebAssemblySignature),
            ContainerKind.Photoshop => sample.StartsWith("8BPS"u8),
            ContainerKind.Vhdx => sample.StartsWith("vhdxfile"u8),
            ContainerKind.GitPack => sample.StartsWith("PACK"u8),
            ContainerKind.OneNote => sample.StartsWith(OneNoteSignature),
            _ => false,
        };

    private static bool IsZip(ReadOnlySpan<byte> sample)
    {
        // ZIP permits a preamble (self-extracting and some producer-specific archives use one).
        // Bound the scan so a random PK sequence deep in encrypted data cannot bless the sample.
        var lastStart = Math.Min(sample.Length - 4, 1024);
        for (var index = 0; index <= lastStart; index++)
        {
            if (sample[index] == 0x50
                && sample[index + 1] == 0x4B
                && (sample[index + 2] == 0x03 && sample[index + 3] == 0x04
                    || sample[index + 2] == 0x05 && sample[index + 3] == 0x06
                    || sample[index + 2] == 0x07 && sample[index + 3] == 0x08))
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsRar(ReadOnlySpan<byte> sample) =>
        sample.StartsWith(Rar4Signature) || sample.StartsWith(Rar5Signature);

    private static bool IsZstandard(ReadOnlySpan<byte> sample) =>
        sample.StartsWith(ZstandardSignature)
        || IsSkippableFrame(sample);

    private static bool IsLz4(ReadOnlySpan<byte> sample) =>
        sample.StartsWith(Lz4Signature)
        || IsSkippableFrame(sample);

    private static bool IsSkippableFrame(ReadOnlySpan<byte> sample) =>
        sample.Length >= 4
        && sample[0] is >= 0x50 and <= 0x5F
        && sample[1] == 0x2A
        && sample[2] == 0x4D
        && sample[3] == 0x18;

    private static bool IsRiff(ReadOnlySpan<byte> sample, ReadOnlySpan<byte> form) =>
        sample.Length >= 12
        && sample.StartsWith("RIFF"u8)
        && sample[8..12].SequenceEqual(form);

    private static bool HasMpegAudioSync(ReadOnlySpan<byte> sample) =>
        sample.Length >= 2 && sample[0] == 0xFF && (sample[1] & 0xE0) == 0xE0;

    private static bool HasAdtsSync(ReadOnlySpan<byte> sample) =>
        sample.Length >= 2 && sample[0] == 0xFF && (sample[1] & 0xF6) == 0xF0;

    private static bool IsJpegXl(ReadOnlySpan<byte> sample) =>
        sample.StartsWith(JpegXlCodestreamSignature) || sample.StartsWith(JpegXlContainerSignature);

    private enum ContainerKind
    {
        None,
        Zip,
        OfficeOpenXml,
        SevenZip,
        Rar,
        GZip,
        BZip2,
        Xz,
        Zstandard,
        Lz4,
        Cabinet,
        CompoundFile,
        Jpeg,
        Png,
        Gif,
        WebP,
        Tiff,
        Icon,
        Pdf,
        Mp3,
        IsoBaseMedia,
        Ebml,
        Avi,
        Flac,
        Ogg,
        Aac,
        Asf,
        JpegXl,
        PortableExecutable,
        WebAssembly,
        Photoshop,
        Vhdx,
        GitPack,
        OneNote,
    }
}
