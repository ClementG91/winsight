using System.Buffers.Binary;
using System.Text;

namespace WinSight.Hijack;

/// <summary>The modules a binary declares it needs, split by how the loader fetches them.</summary>
/// <param name="Imports">
/// Bound at load time. If one of these cannot be found the process does not start, so a missing
/// entry here is both louder and more reliably reached by an attacker.
/// </param>
/// <param name="DelayImports">
/// Fetched on first use. A missing one costs nothing until the feature that needs it runs, which is
/// exactly why it is worth reporting separately: it can sit unnoticed for the life of a machine.
/// </param>
public sealed record PeImportSet(IReadOnlyList<string> Imports, IReadOnlyList<string> DelayImports)
{
    public static readonly PeImportSet Empty = new([], []);

    public bool IsEmpty => Imports.Count == 0 && DelayImports.Count == 0;
}

/// <summary>
/// Reads the import and delay-import tables out of a PE image.
/// </summary>
/// <remarks>
/// <b>Why a parser rather than a loader call.</b> Asking Windows what a binary imports means loading
/// it, which runs its initialisation code — unacceptable in a scanner pointed at files it already
/// suspects. Reading the headers is inert.
///
/// <b>Every read is bounds-checked and every count is capped, on purpose.</b> This parses files an
/// attacker may have written, and the whole point of the scan is to be aimed at the suspicious ones.
/// A truncated, hostile or simply non-PE file must yield <see cref="PeImportSet.Empty"/> rather than
/// an exception or a wild read: the caller cannot tell a malformed binary from a boring one, and
/// neither can be allowed to end the sweep.
///
/// It reads the on-disk layout, so RVAs are translated through the section table rather than assumed
/// to be file offsets — those differ for every real binary and agree only for trivial handcrafted
/// ones, which is the classic way a parser like this passes its tests and fails on Windows.
/// </remarks>
public static class PeImports
{
    private const ushort DosSignature = 0x5A4D;          // "MZ"
    private const uint PeSignature = 0x0000_4550;        // "PE\0\0"
    private const ushort Pe32 = 0x10B;
    private const ushort Pe32Plus = 0x20B;

    private const int ImportDirectoryIndex = 1;
    private const int DelayImportDirectoryIndex = 13;

    private const int ImportDescriptorSize = 20;
    private const int ImportDescriptorNameOffset = 12;
    private const int DelayDescriptorSize = 32;
    private const int DelayDescriptorNameOffset = 4;

    /// <summary>A hostile import table must not become an unbounded loop or allocation.</summary>
    private const int MaxDescriptors = 4096;
    private const int MaxNameLength = 255;
    private const int MaxSections = 96;

    /// <summary>
    /// The imports declared by <paramref name="path"/>, or <see cref="PeImportSet.Empty"/> when the
    /// file cannot be read or is not a PE image.
    /// </summary>
    /// <summary>A sweep reads hundreds of binaries; one pathological file must not dominate it.</summary>
    private const long MaxImageBytes = 64 * 1024 * 1024;

    public static PeImportSet ReadFile(string path)
    {
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists || file.Length is 0 or > MaxImageBytes)
            {
                return PeImportSet.Empty;
            }
            return Read(File.ReadAllBytes(path));
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or NotSupportedException
                                     or System.Security.SecurityException)
        {
            return PeImportSet.Empty;
        }
    }

    public static PeImportSet Read(ReadOnlySpan<byte> image)
    {
        if (!TryU16(image, 0, out var dos) || dos != DosSignature
            || !TryU32(image, 0x3C, out var peOffset)
            || !TryU32(image, peOffset, out var pe) || pe != PeSignature)
        {
            return PeImportSet.Empty;
        }

        var coff = peOffset + 4;
        if (!TryU16(image, coff + 2, out var sectionCount)
            || !TryU16(image, coff + 16, out var optionalSize)
            || sectionCount is 0 or > MaxSections)
        {
            return PeImportSet.Empty;
        }

        var optional = coff + 20;
        if (!TryU16(image, optional, out var magic))
        {
            return PeImportSet.Empty;
        }

        // The data directory sits at a different offset in the two optional-header shapes, and
        // getting this wrong reads the wrong table rather than failing, so both are explicit.
        var (countOffset, directoryBase) = magic switch
        {
            Pe32 => (optional + 92u, optional + 96u),
            Pe32Plus => (optional + 108u, optional + 112u),
            _ => (0u, 0u),
        };
        if (directoryBase == 0 || !TryU32(image, countOffset, out var directoryCount))
        {
            return PeImportSet.Empty;
        }

        var sections = ReadSections(image, optional + optionalSize, sectionCount);
        if (sections.Count == 0)
        {
            return PeImportSet.Empty;
        }

        var imports = ReadDescriptorNames(
            image, sections, directoryBase, directoryCount, ImportDirectoryIndex,
            ImportDescriptorSize, ImportDescriptorNameOffset, delayLoad: false);
        var delayImports = ReadDescriptorNames(
            image, sections, directoryBase, directoryCount, DelayImportDirectoryIndex,
            DelayDescriptorSize, DelayDescriptorNameOffset, delayLoad: true);

        return imports.Count == 0 && delayImports.Count == 0
            ? PeImportSet.Empty
            : new PeImportSet(imports, delayImports);
    }

    private readonly record struct Section(uint VirtualAddress, uint VirtualSize, uint RawAddress, uint RawSize);

    private static List<Section> ReadSections(ReadOnlySpan<byte> image, uint at, ushort count)
    {
        var sections = new List<Section>(count);
        for (var i = 0; i < count; i++)
        {
            var header = at + ((uint)i * 40);
            if (!TryU32(image, header + 8, out var virtualSize)
                || !TryU32(image, header + 12, out var virtualAddress)
                || !TryU32(image, header + 16, out var rawSize)
                || !TryU32(image, header + 20, out var rawAddress))
            {
                break;
            }
            sections.Add(new Section(virtualAddress, virtualSize, rawAddress, rawSize));
        }
        return sections;
    }

    /// <summary>
    /// Translates a relative virtual address to an offset in the file on disk.
    /// </summary>
    /// <remarks>
    /// A section's virtual size is routinely larger than what is stored, so the readable window is
    /// the smaller of the two. Clamping to the raw size keeps a crafted section header from pointing
    /// this parser past the end of the data it was handed.
    /// </remarks>
    private static bool TryOffset(List<Section> sections, uint rva, out uint offset)
    {
        foreach (var section in sections)
        {
            var span = Math.Min(section.VirtualSize == 0 ? section.RawSize : section.VirtualSize, section.RawSize);
            if (span != 0 && rva >= section.VirtualAddress && rva < section.VirtualAddress + span)
            {
                offset = section.RawAddress + (rva - section.VirtualAddress);
                return true;
            }
        }
        offset = 0;
        return false;
    }

    private static List<string> ReadDescriptorNames(
        ReadOnlySpan<byte> image,
        List<Section> sections,
        uint directoryBase,
        uint directoryCount,
        int directoryIndex,
        uint descriptorSize,
        uint nameOffset,
        bool delayLoad)
    {
        var names = new List<string>();
        if (directoryIndex >= directoryCount
            || !TryU32(image, directoryBase + ((uint)directoryIndex * 8), out var tableRva)
            || tableRva == 0
            || !TryOffset(sections, tableRva, out var table))
        {
            return names;
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < MaxDescriptors; i++)
        {
            var descriptor = table + ((uint)i * descriptorSize);
            if (!IsReadable(image, descriptor, descriptorSize))
            {
                break;
            }
            // The table ends at an all-zero descriptor. Checking the whole entry rather than one
            // field avoids walking off into whatever follows when a field happens to be zero.
            if (IsZero(image.Slice((int)descriptor, (int)descriptorSize)))
            {
                break;
            }

            // Delay descriptors were address-based before the RVA flag existed. Reading one of those
            // as an RVA lands somewhere arbitrary, so they are skipped rather than guessed at.
            if (delayLoad && (!TryU32(image, descriptor, out var attributes) || (attributes & 1) == 0))
            {
                break;
            }

            if (TryU32(image, descriptor + nameOffset, out var nameRva)
                && nameRva != 0
                && TryOffset(sections, nameRva, out var nameAt)
                && ReadAsciiZ(image, nameAt) is { Length: > 0 } name
                && seen.Add(name))
            {
                names.Add(name);
            }
        }
        return names;
    }

    private static string? ReadAsciiZ(ReadOnlySpan<byte> image, uint at)
    {
        if (at >= (uint)image.Length)
        {
            return null;
        }
        var span = image[(int)at..];
        var end = span.IndexOf((byte)0);
        if (end < 0)
        {
            end = span.Length;
        }
        if (end is 0 or > MaxNameLength)
        {
            return null;
        }
        return Encoding.ASCII.GetString(span[..end]);
    }

    private static bool IsZero(ReadOnlySpan<byte> span)
    {
        foreach (var value in span)
        {
            if (value != 0)
            {
                return false;
            }
        }
        return true;
    }

    private static bool IsReadable(ReadOnlySpan<byte> image, uint at, uint length) =>
        at <= (uint)image.Length && length <= (uint)image.Length - at;

    private static bool TryU16(ReadOnlySpan<byte> image, uint at, out ushort value)
    {
        if (!IsReadable(image, at, sizeof(ushort)))
        {
            value = 0;
            return false;
        }
        value = BinaryPrimitives.ReadUInt16LittleEndian(image.Slice((int)at, sizeof(ushort)));
        return true;
    }

    private static bool TryU32(ReadOnlySpan<byte> image, uint at, out uint value)
    {
        if (!IsReadable(image, at, sizeof(uint)))
        {
            value = 0;
            return false;
        }
        value = BinaryPrimitives.ReadUInt32LittleEndian(image.Slice((int)at, sizeof(uint)));
        return true;
    }
}
