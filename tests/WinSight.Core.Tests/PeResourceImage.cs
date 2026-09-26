using System.Buffers.Binary;
using System.Text;

namespace WinSight.Core.Tests;

/// <summary>
/// Builds small but structurally honest PE images carrying resources, and the version blocks they
/// hold. RVAs differ from file offsets throughout, so a parser that confuses them fails here.
/// </summary>
internal static class PeResourceImage
{
    public const uint SectionRva = 0x3000;
    public const uint SectionRaw = 0x400;

    private const uint Coff = 0x84;
    private const uint Optional = Coff + 20;

    /// <summary>A PE whose <c>.rsrc</c> section holds each resource once, in language 0x0409.</summary>
    public static byte[] Build(IReadOnlyList<(ushort Type, ushort Id, byte[] Data)> resources, bool pe32Plus = true)
    {
        var tree = BuildTree(resources);
        var rawSize = (uint)((tree.Length + 0x1FF) & ~0x1FF);
        var image = new byte[SectionRaw + rawSize];
        var optionalSize = pe32Plus ? (ushort)240 : (ushort)224;

        image[0] = (byte)'M';
        image[1] = (byte)'Z';
        WriteU32(image, 0x3C, 0x80);
        image[0x80] = (byte)'P';
        image[0x81] = (byte)'E';
        WriteU16(image, Coff, 0x8664);
        WriteU16(image, Coff + 2, 1);
        WriteU16(image, Coff + 16, optionalSize);

        WriteU16(image, Optional, pe32Plus ? (ushort)0x20B : (ushort)0x10B);
        var directoryCountAt = Optional + (pe32Plus ? 108u : 92u);
        var directoryBase = Optional + (pe32Plus ? 112u : 96u);
        WriteU32(image, directoryCountAt, 16);
        WriteU32(image, directoryBase + (2 * 8), SectionRva);
        WriteU32(image, directoryBase + (2 * 8) + 4, (uint)tree.Length);

        var section = Optional + optionalSize;
        Encoding.ASCII.GetBytes(".rsrc").CopyTo(image, (int)section);
        WriteU32(image, section + 8, (uint)tree.Length);   // VirtualSize
        WriteU32(image, section + 12, SectionRva);         // VirtualAddress
        WriteU32(image, section + 16, rawSize);            // SizeOfRawData
        WriteU32(image, section + 20, SectionRaw);         // PointerToRawData

        tree.CopyTo(image, (int)SectionRaw);
        return image;
    }

    /// <summary>File offset of an offset inside the resource tree.</summary>
    public static int TreeOffset(int offset) => (int)SectionRaw + offset;

    /// <summary>
    /// Root, one directory per type, one per name, one data entry per resource, then the data.
    /// Directory offsets are relative to the root; data entries hold RVAs.
    /// </summary>
    private static byte[] BuildTree(IReadOnlyList<(ushort Type, ushort Id, byte[] Data)> resources)
    {
        var types = resources.GroupBy(r => r.Type).OrderBy(g => g.Key).ToList();
        var nameDirectoryCount = resources.Count;
        var rootSize = 16 + (8 * types.Count);
        var typeSizes = types.Sum(t => 16 + (8 * t.Count()));
        var nameSizes = nameDirectoryCount * (16 + 8);
        var entriesStart = rootSize + typeSizes + nameSizes;
        var dataStart = entriesStart + (16 * resources.Count);
        var dataSize = resources.Sum(r => (r.Data.Length + 7) & ~7);
        var tree = new byte[dataStart + dataSize];

        WriteDirectoryHeader(tree, 0, (ushort)types.Count);
        var typeAt = rootSize;
        var nameAt = rootSize + typeSizes;
        var entryAt = entriesStart;
        var dataAt = dataStart;
        for (var t = 0; t < types.Count; t++)
        {
            WriteU32(tree, (uint)(16 + (t * 8)), types[t].Key);
            WriteU32(tree, (uint)(16 + (t * 8) + 4), 0x8000_0000 | (uint)typeAt);
            var names = types[t].OrderBy(r => r.Id).ToList();
            WriteDirectoryHeader(tree, typeAt, (ushort)names.Count);
            for (var n = 0; n < names.Count; n++)
            {
                WriteU32(tree, (uint)(typeAt + 16 + (n * 8)), names[n].Id);
                WriteU32(tree, (uint)(typeAt + 16 + (n * 8) + 4), 0x8000_0000 | (uint)nameAt);
                WriteDirectoryHeader(tree, nameAt, 1);
                WriteU32(tree, (uint)(nameAt + 16), 0x0409);
                WriteU32(tree, (uint)(nameAt + 20), (uint)entryAt);
                WriteU32(tree, (uint)entryAt, SectionRva + (uint)dataAt);
                WriteU32(tree, (uint)(entryAt + 4), (uint)names[n].Data.Length);
                names[n].Data.CopyTo(tree, dataAt);
                nameAt += 24;
                entryAt += 16;
                dataAt += (names[n].Data.Length + 7) & ~7;
            }
            typeAt += 16 + (8 * names.Count);
        }
        return tree;
    }

    private static void WriteDirectoryHeader(byte[] tree, int at, ushort idEntries) =>
        WriteU16(tree, (uint)(at + 14), idEntries);

    /// <summary>
    /// A <c>VS_VERSIONINFO</c> with one string table per entry of <paramref name="tables"/> and,
    /// when given, a <c>Translation</c> naming <paramref name="translation"/> ("040904B0").
    /// </summary>
    public static byte[] VersionInfo(string? translation, params (string Table, (string Key, string Value)[] Strings)[] tables)
    {
        var fixedInfo = new byte[52];
        WriteU32(fixedInfo, 0, 0xFEEF04BD);
        var stringTables = tables
            .Select(table => Block(table.Table, 1, [], 0,
                table.Strings.Select(s => Block(s.Key, 1, Encoding.Unicode.GetBytes(s.Value + "\0"), s.Value.Length + 1)).ToArray()))
            .ToArray();
        var children = new List<byte[]> { Block("StringFileInfo", 1, [], 0, stringTables) };
        if (translation is not null)
        {
            var value = new byte[4];
            WriteU16(value, 0, Convert.ToUInt16(translation[..4], 16));
            WriteU16(value, 2, Convert.ToUInt16(translation[4..], 16));
            children.Add(Block("VarFileInfo", 1, [], 0, Block("Translation", 0, value, 4)));
        }
        return Block("VS_VERSION_INFO", 0, fixedInfo, fixedInfo.Length, [.. children]);
    }

    /// <summary>
    /// One block: header, key, value and children, each part aligned to 32 bits. The length covers
    /// the children but not padding after the last one, as the format specifies.
    /// </summary>
    public static byte[] Block(string key, ushort type, byte[] value, int valueLengthField, params byte[][] children)
    {
        var block = new List<byte>(new byte[6]);
        block.AddRange(Encoding.Unicode.GetBytes(key + "\0"));
        Pad(block);
        block.AddRange(value);
        foreach (var child in children)
        {
            Pad(block);
            block.AddRange(child);
        }
        var bytes = block.ToArray();
        WriteU16(bytes, 0, (ushort)bytes.Length);
        WriteU16(bytes, 2, (ushort)valueLengthField);
        WriteU16(bytes, 4, type);
        return bytes;
    }

    private static void Pad(List<byte> block)
    {
        while (block.Count % 4 != 0)
        {
            block.Add(0);
        }
    }

    public static void WriteU16(byte[] image, uint at, ushort value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan((int)at), value);

    public static void WriteU32(byte[] image, uint at, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan((int)at), value);
}
