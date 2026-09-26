using System.Buffers.Binary;
using System.Text;

namespace WinSight.Core;

/// <summary>
/// Reads the strings of an image's own <c>VS_VERSIONINFO</c> resource - the block Explorer shows as
/// "File version" and "Original filename" - through a handle WinSight already holds.
/// </summary>
/// <remarks>
/// <b>The image's own resource, never its language file.</b> <c>FileVersionInfo</c> asks
/// <c>GetFileVersionInfoEx</c> for the localised resource, which Windows takes from
/// <c>en-US\powershell.exe.mui</c> beside the image. Measured on Windows 11 26200: the compiled-in
/// name of <c>powershell.exe</c>, <c>cmd.exe</c>, <c>mshta.exe</c>, <c>rundll32.exe</c> and
/// <c>regsvr32.exe</c> all read <c>*.MUI</c>. That took every genuine interpreter out of the
/// interpreter table (WS-74). A renamed copy has no language file beside it, which is why the
/// masquerade case looked right in isolation.
/// </remarks>
public static class VersionResource
{
    /// <summary><c>VS_VERSION_INFO</c>, the resource identifier Windows reads.</summary>
    private const ushort VersionInfoId = 1;

    /// <summary><c>wLength</c> is a 16-bit field, so no genuine block is larger.</summary>
    private const int MaximumBytes = ushort.MaxValue;

    private const int MaxChildren = 1024;
    private const int MaxKeyBytes = 256;
    private const ushort TextValue = 1;

    /// <summary>
    /// The US English tables <c>FileVersionInfo</c> falls back to, in its order, after the first
    /// translation the file declares.
    /// </summary>
    private static readonly string[] FallbackTables = ["040904B0", "040904E4", "04090000"];

    /// <summary>
    /// The name the vendor compiled into the acquired image (<c>OriginalFilename</c>), or null when it
    /// has none, is not a PE image, or its data is not on this machine.
    /// </summary>
    /// <remarks>
    /// Read through the lease's own handle: the name belongs to the file the lease acquired, and a
    /// cloud-only or offline file is not read at all, so nothing is ever downloaded (WS-40).
    /// </remarks>
    /// <exception cref="IOException">The file could not be read.</exception>
    public static string? ReadOriginalFileName(AutomaticFileAccess.LocalPathLease lease)
    {
        ArgumentNullException.ThrowIfNull(lease);
        if (lease.IsDirectory || !lease.DataIsLocal)
        {
            return null;
        }
        using var stream = lease.OpenRead(FileOptions.RandomAccess);
        var data = PeResources.Read(stream, PeResources.VersionType, VersionInfoId, MaximumBytes);
        return data is null ? null : OriginalFileName(data);
    }

    /// <summary>The <c>OriginalFilename</c> string of a <c>VS_VERSIONINFO</c> block, or null.</summary>
    public static string? OriginalFileName(ReadOnlySpan<byte> versionInfo) =>
        ReadString(versionInfo, "OriginalFilename");

    /// <summary>
    /// A string of the first table that has it, trying the file's own first translation, then the
    /// US English fallbacks, then every table in file order.
    /// </summary>
    internal static string? ReadString(ReadOnlySpan<byte> versionInfo, string key)
    {
        if (!TryBlock(versionInfo, 0, versionInfo.Length, out var root)
            || !root.Key.Equals("VS_VERSION_INFO", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var tables = new List<Block>();
        string? translation = null;
        foreach (var child in Children(versionInfo, root))
        {
            if (child.Key.Equals("StringFileInfo", StringComparison.OrdinalIgnoreCase))
            {
                tables.AddRange(Children(versionInfo, child));
            }
            else if (child.Key.Equals("VarFileInfo", StringComparison.OrdinalIgnoreCase))
            {
                translation ??= FirstTranslation(versionInfo, child);
            }
        }

        string[] preferred = translation is null ? FallbackTables : [translation, .. FallbackTables];
        foreach (var candidate in preferred)
        {
            foreach (var table in tables)
            {
                if (table.Key.Equals(candidate, StringComparison.OrdinalIgnoreCase)
                    && FindString(versionInfo, table, key) is { Length: > 0 } value)
                {
                    return value;
                }
            }
        }
        foreach (var table in tables)
        {
            if (FindString(versionInfo, table, key) is { Length: > 0 } value)
            {
                return value;
            }
        }
        return null;
    }

    /// <summary>
    /// One node of the tree: <c>wLength</c>, <c>wValueLength</c>, <c>wType</c>, a NUL-terminated
    /// UTF-16 key, a value, then children, each part aligned to 32 bits from the block's start.
    /// </summary>
    private readonly record struct Block(int End, string Key, ushort Type, int ValueStart, int ChildrenStart);

    private static bool TryBlock(ReadOnlySpan<byte> data, int start, int limit, out Block block)
    {
        block = default;
        if (start < 0 || limit - start < 6)
        {
            return false;
        }
        int length = BinaryPrimitives.ReadUInt16LittleEndian(data[start..]);
        if (length < 6 || length > limit - start)
        {
            return false;
        }
        var end = start + length;
        int valueLength = BinaryPrimitives.ReadUInt16LittleEndian(data[(start + 2)..]);
        var type = BinaryPrimitives.ReadUInt16LittleEndian(data[(start + 4)..]);

        var keyStart = start + 6;
        var keyEnd = keyStart;
        while (keyEnd <= end - 2 && (data[keyEnd] | data[keyEnd + 1]) != 0)
        {
            keyEnd += 2;
        }
        if (keyEnd > end - 2 || keyEnd - keyStart > MaxKeyBytes)
        {
            return false;
        }
        var key = Encoding.Unicode.GetString(data[keyStart..keyEnd]);

        var valueStart = Math.Min(Align(keyEnd + 2), end);
        // A text value is counted in characters, a binary one in bytes.
        var valueBytes = type == TextValue ? valueLength * 2 : valueLength;
        var childrenStart = Math.Min(Align(valueStart + valueBytes), end);
        block = new Block(end, key, type, valueStart, childrenStart);
        return true;
    }

    private static List<Block> Children(ReadOnlySpan<byte> data, Block parent)
    {
        var children = new List<Block>();
        var at = parent.ChildrenStart;
        while (children.Count < MaxChildren && TryBlock(data, at, parent.End, out var child))
        {
            children.Add(child);
            at = Align(child.End);
        }
        return children;
    }

    private static string? FindString(ReadOnlySpan<byte> data, Block table, string key)
    {
        foreach (var entry in Children(data, table))
        {
            if (entry.Key.Equals(key, StringComparison.OrdinalIgnoreCase))
            {
                return ReadText(data, entry);
            }
        }
        return null;
    }

    /// <summary>
    /// A string value, read up to its terminator. Some compilers count a text value in bytes rather
    /// than characters, so the terminator decides and the length field only bounds.
    /// </summary>
    private static string ReadText(ReadOnlySpan<byte> data, Block entry)
    {
        var at = entry.ValueStart;
        while (at <= entry.End - 2 && (data[at] | data[at + 1]) != 0)
        {
            at += 2;
        }
        return Encoding.Unicode.GetString(data[entry.ValueStart..at]).Trim();
    }

    /// <summary>The first language and code page the file declares, as its table key: "040904B0".</summary>
    private static string? FirstTranslation(ReadOnlySpan<byte> data, Block varFileInfo)
    {
        foreach (var variable in Children(data, varFileInfo))
        {
            if (variable.Key.Equals("Translation", StringComparison.OrdinalIgnoreCase)
                && variable.ValueStart <= variable.End - 4)
            {
                var language = BinaryPrimitives.ReadUInt16LittleEndian(data[variable.ValueStart..]);
                var codePage = BinaryPrimitives.ReadUInt16LittleEndian(data[(variable.ValueStart + 2)..]);
                return $"{language:X4}{codePage:X4}";
            }
        }
        return null;
    }

    private static int Align(int offset) => (offset + 3) & ~3;
}
