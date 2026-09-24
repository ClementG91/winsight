using System.Buffers.Binary;

namespace WinSight.Core;

/// <summary>
/// Reads one resource out of a PE image through a stream the caller already holds, without loading
/// the image.
/// </summary>
/// <remarks>
/// <b>Why not the Win32 resource and version APIs.</b> <c>GetFileVersionInfo</c> and
/// <c>LoadLibraryEx(LOAD_LIBRARY_AS_DATAFILE)</c> take a path. They open the file again, so they
/// read whatever the path names by then, and on a cloud-only file they ask its provider to download
/// it. An automatic read must do neither (WS-40). <c>GetFileVersionInfo</c> also substitutes the
/// language resource file (<c>en-US\cmd.exe.mui</c>) for the image's own resource. That is how the
/// compiled-in name of every Windows interpreter read <c>Cmd.Exe.MUI</c> (WS-74).
///
/// <b>Every read is bounded.</b> The file may be hostile. Offsets are translated through the section
/// table and checked against the stream. Directory entries are capped, and the tree is walked to its
/// fixed depth of three, so a directory that points back at itself ends the walk instead of looping.
/// A resource larger than the caller's cap is refused, not truncated.
/// </remarks>
public static class PeResources
{
    /// <summary><c>RT_VERSION</c>.</summary>
    public const ushort VersionType = 16;

    /// <summary><c>RT_MANIFEST</c>.</summary>
    public const ushort ManifestType = 24;

    private const ushort DosSignature = 0x5A4D;          // "MZ"
    private const uint PeSignature = 0x0000_4550;        // "PE\0\0"
    private const ushort Pe32 = 0x10B;
    private const ushort Pe32Plus = 0x20B;
    private const int ResourceDirectoryIndex = 2;
    private const int SectionHeaderSize = 40;
    private const int MaxSections = 96;
    private const int MaxEntriesPerDirectory = 4096;
    private const uint SubdirectoryFlag = 0x8000_0000;

    /// <summary>
    /// The bytes of the resource of <paramref name="type"/> with the numeric identifier
    /// <paramref name="name"/>, in its first language. Null when the image has no such resource,
    /// is not a PE image, is malformed, or the resource is larger than
    /// <paramref name="maximumBytes"/>.
    /// </summary>
    /// <exception cref="IOException">The stream failed or shrank while it was read.</exception>
    public static byte[]? Read(Stream image, ushort type, ushort name, int maximumBytes)
    {
        ArgumentNullException.ThrowIfNull(image);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumBytes);
        if (!image.CanSeek || !image.CanRead)
        {
            throw new ArgumentException("The image stream must be readable and seekable.", nameof(image));
        }
        var reader = new Reader(image);
        if (!TryReadLayout(reader, out var sections, out var root)
            || !TryFindEntry(reader, sections, root, 0, type, out var typeEntry)
            || (typeEntry & SubdirectoryFlag) == 0
            || !TryFindEntry(reader, sections, root, typeEntry & ~SubdirectoryFlag, name, out var nameEntry)
            || (nameEntry & SubdirectoryFlag) == 0
            // Any language: an image carries one version resource and one manifest per identifier.
            || !TryFindEntry(reader, sections, root, nameEntry & ~SubdirectoryFlag, id: null, out var languageEntry)
            || (languageEntry & SubdirectoryFlag) != 0)
        {
            return null;
        }

        // IMAGE_RESOURCE_DATA_ENTRY: OffsetToData (an RVA, unlike every offset above), Size.
        Span<byte> dataEntry = stackalloc byte[8];
        if (!TryReadRva(reader, sections, (ulong)root + languageEntry, dataEntry))
        {
            return null;
        }
        var dataRva = BinaryPrimitives.ReadUInt32LittleEndian(dataEntry);
        var size = BinaryPrimitives.ReadUInt32LittleEndian(dataEntry[4..]);
        if (size == 0 || size > (uint)maximumBytes)
        {
            return null;
        }
        var data = new byte[size];
        return TryReadRva(reader, sections, dataRva, data) ? data : null;
    }

    private readonly record struct Section(uint VirtualAddress, uint Span, uint RawAddress);

    /// <summary>The section table and the resource directory's RVA, from the image headers.</summary>
    private static bool TryReadLayout(Reader reader, out Section[] sections, out uint resourceRoot)
    {
        sections = [];
        resourceRoot = 0;
        Span<byte> dos = stackalloc byte[64];
        if (!reader.TryRead(0, dos) || BinaryPrimitives.ReadUInt16LittleEndian(dos) != DosSignature)
        {
            return false;
        }
        long peOffset = BinaryPrimitives.ReadUInt32LittleEndian(dos[0x3C..]);

        // "PE\0\0", then IMAGE_FILE_HEADER: NumberOfSections at 2, SizeOfOptionalHeader at 16.
        Span<byte> header = stackalloc byte[24];
        if (!reader.TryRead(peOffset, header) || BinaryPrimitives.ReadUInt32LittleEndian(header) != PeSignature)
        {
            return false;
        }
        var sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(header[6..]);
        var optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(header[20..]);
        if (sectionCount is 0 or > MaxSections)
        {
            return false;
        }

        // The data directories sit at a different offset in the two optional-header shapes.
        var optional = peOffset + 24;
        Span<byte> magic = stackalloc byte[2];
        if (!reader.TryRead(optional, magic))
        {
            return false;
        }
        var (countOffset, directoriesOffset) = BinaryPrimitives.ReadUInt16LittleEndian(magic) switch
        {
            Pe32 => (92, 96),
            Pe32Plus => (108, 112),
            _ => (0, 0),
        };
        var resourceOffset = directoriesOffset + (ResourceDirectoryIndex * 8);
        if (directoriesOffset == 0 || optionalSize < resourceOffset + 8)
        {
            return false;
        }
        Span<byte> directories = stackalloc byte[resourceOffset + 8];
        if (!reader.TryRead(optional, directories)
            || BinaryPrimitives.ReadUInt32LittleEndian(directories[countOffset..]) <= ResourceDirectoryIndex)
        {
            return false;
        }
        resourceRoot = BinaryPrimitives.ReadUInt32LittleEndian(directories[resourceOffset..]);
        if (resourceRoot == 0)
        {
            return false;
        }

        var table = new byte[sectionCount * SectionHeaderSize];
        if (!reader.TryRead(optional + optionalSize, table))
        {
            return false;
        }
        sections = new Section[sectionCount];
        for (var i = 0; i < sectionCount; i++)
        {
            var at = table.AsSpan(i * SectionHeaderSize);
            var virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(at[8..]);
            var virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(at[12..]);
            var rawSize = BinaryPrimitives.ReadUInt32LittleEndian(at[16..]);
            var rawAddress = BinaryPrimitives.ReadUInt32LittleEndian(at[20..]);
            // What is both mapped and stored: a virtual size is routinely larger than the data on
            // disk, and clamping to the raw size keeps a crafted header from reaching past it.
            sections[i] = new Section(virtualAddress, Math.Min(virtualSize == 0 ? rawSize : virtualSize, rawSize), rawAddress);
        }
        return true;
    }

    /// <summary>
    /// The OffsetToData field of the entry with numeric identifier <paramref name="id"/> (the first
    /// entry when null) in the directory at <paramref name="directory"/>, relative to the root.
    /// </summary>
    private static bool TryFindEntry(
        Reader reader, Section[] sections, uint root, uint directory, ushort? id, out uint offsetToData)
    {
        offsetToData = 0;
        // IMAGE_RESOURCE_DIRECTORY: NumberOfNamedEntries at 12 and NumberOfIdEntries at 14, then the
        // entries - named ones first, as the format requires.
        Span<byte> header = stackalloc byte[16];
        if (!TryReadRva(reader, sections, (ulong)root + directory, header))
        {
            return false;
        }
        var named = BinaryPrimitives.ReadUInt16LittleEndian(header[12..]);
        var total = named + BinaryPrimitives.ReadUInt16LittleEndian(header[14..]);
        if (total is 0 or > MaxEntriesPerDirectory)
        {
            return false;
        }
        var entries = new byte[total * 8];
        if (!TryReadRva(reader, sections, (ulong)root + directory + 16, entries))
        {
            return false;
        }
        for (var i = id is null ? 0 : named; i < total; i++)
        {
            var nameField = BinaryPrimitives.ReadUInt32LittleEndian(entries.AsSpan(i * 8));
            if (id is null || nameField == id.Value)
            {
                offsetToData = BinaryPrimitives.ReadUInt32LittleEndian(entries.AsSpan((i * 8) + 4));
                return true;
            }
        }
        return false;
    }

    /// <summary>Reads <paramref name="destination"/> at an RVA, entirely inside one section.</summary>
    private static bool TryReadRva(Reader reader, Section[] sections, ulong rva, Span<byte> destination)
    {
        foreach (var section in sections)
        {
            if (rva >= section.VirtualAddress
                && rva - section.VirtualAddress + (ulong)destination.Length <= section.Span)
            {
                return reader.TryRead((long)(section.RawAddress + (rva - section.VirtualAddress)), destination);
            }
        }
        return false;
    }

    private sealed class Reader(Stream stream)
    {
        private readonly long _length = stream.Length;

        public bool TryRead(long offset, Span<byte> destination)
        {
            if (offset < 0 || offset > _length - destination.Length)
            {
                return false;
            }
            stream.Position = offset;
            stream.ReadExactly(destination);
            return true;
        }
    }
}
