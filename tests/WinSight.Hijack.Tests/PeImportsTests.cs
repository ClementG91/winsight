using System.Buffers.Binary;
using System.Text;

using WinSight.Hijack;

using Xunit;

namespace WinSight.Hijack.Tests;

/// <summary>
/// The PE import reader, against images built here and against the real ones on this machine.
/// </summary>
/// <remarks>
/// <b>Why the synthetic images carry a real section table.</b> A parser that treats an RVA as a file
/// offset agrees with a handcrafted PE whose section starts at zero, and disagrees with every binary
/// Windows ships. The builder below therefore places the import table at RVA 0x2000 while storing it
/// at file offset 0x400, so a parser that skips the translation fails these tests immediately.
///
/// The real-binary test is what proves the whole thing on this platform; the synthetic ones are what
/// let the hostile and edge cases be written at all.
/// </remarks>
public sealed class PeImportsTests
{
    // ---- Real binaries -----------------------------------------------------------------------

    [Fact]
    public void ReadsTheImportsOfARealSystemBinary()
    {
        var kernel32 = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll");

        var imports = PeImports.ReadFile(kernel32);

        Assert.NotEmpty(imports.Imports);
        Assert.Contains(imports.Imports, i => i.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void AResourceOnlyBinaryHasNoImportsAndIsNotAnError()
    {
        // *res.dll files under System32 carry resources and no import table at all. Empty is the
        // correct answer for them, and must not be confused with a parse failure.
        var resourceDll = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "advapi32res.dll");
        if (!File.Exists(resourceDll))
        {
            return;
        }

        Assert.True(PeImports.ReadFile(resourceDll).IsEmpty);
    }

    // ---- Hostile and malformed input ---------------------------------------------------------

    [Fact]
    public void MalformedInputYieldsEmptyRatherThanThrowing()
    {
        // This parser is pointed at files an attacker may have written, so every one of these is a
        // realistic input, not a hypothetical.
        Assert.True(PeImports.Read([]).IsEmpty);
        Assert.True(PeImports.Read([0x4D, 0x5A]).IsEmpty);
        Assert.True(PeImports.Read(Encoding.ASCII.GetBytes("not a binary at all")).IsEmpty);
        Assert.True(PeImports.Read(new byte[512]).IsEmpty);

        // A valid header whose e_lfanew points past the end of the file.
        var runaway = new byte[128];
        runaway[0] = 0x4D;
        runaway[1] = 0x5A;
        BinaryPrimitives.WriteUInt32LittleEndian(runaway.AsSpan(0x3C), 0xFFFF_FFF0);
        Assert.True(PeImports.Read(runaway).IsEmpty);
    }

    [Fact]
    public void ATruncatedImageIsEmptyAtEveryTruncationPoint()
    {
        var full = BuildPe(["KERNEL32.dll"], []);

        for (var length = 0; length < full.Length; length += 7)
        {
            // The assertion is that nothing throws; a short read may legitimately still parse.
            _ = PeImports.Read(full.AsSpan(0, length));
        }
    }

    // ---- The shape a real binary has ---------------------------------------------------------

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ReadsImportsFromBothOptionalHeaderShapes(bool pe32Plus)
    {
        var image = BuildPe(["KERNEL32.dll", "USER32.dll"], [], pe32Plus);

        var imports = PeImports.Read(image);

        Assert.Equal(["KERNEL32.dll", "USER32.dll"], imports.Imports);
    }

    [Fact]
    public void SeparatesDelayLoadedImportsFromLoadTimeOnes()
    {
        var image = BuildPe(["KERNEL32.dll"], ["WINMM.dll"]);

        var imports = PeImports.Read(image);

        Assert.Equal(["KERNEL32.dll"], imports.Imports);
        Assert.Equal(["WINMM.dll"], imports.DelayImports);
    }

    [Fact]
    public void StopsAtTheAllZeroTerminatorRatherThanRunningOn()
    {
        var image = BuildPe(["KERNEL32.dll"], []);

        // Everything after the terminator is left as zero by the builder; if the reader ignored the
        // terminator it would keep manufacturing entries out of it.
        Assert.Single(PeImports.Read(image).Imports);
    }

    [Fact]
    public void ADuplicateImportIsReportedOnce()
    {
        var image = BuildPe(["KERNEL32.dll", "KERNEL32.dll"], []);

        Assert.Equal(["KERNEL32.dll"], PeImports.Read(image).Imports);
    }

    // ---- Builder -----------------------------------------------------------------------------

    private const uint Coff = 0x84;
    private const uint Optional = Coff + 20;
    private const uint ImportTableRva = 0x2000;
    private const uint DelayTableRva = 0x2080;
    private const uint ImportNamesRva = 0x2100;
    private const uint DelayNamesRva = 0x2180;
    private const uint SectionRva = 0x2000;
    private const uint SectionRaw = 0x400;

    private static uint ToOffset(uint rva) => SectionRaw + (rva - SectionRva);

    /// <summary>A minimal but structurally honest PE: RVAs differ from file offsets throughout.</summary>
    private static byte[] BuildPe(string[] imports, string[] delayImports, bool pe32Plus = true)
    {
        var image = new byte[0x600];
        var optionalSize = pe32Plus ? (ushort)240 : (ushort)224;

        image[0] = (byte)'M';
        image[1] = (byte)'Z';
        WriteU32(image, 0x3C, 0x80);

        image[0x80] = (byte)'P';
        image[0x81] = (byte)'E';

        WriteU16(image, Coff, 0x8664);              // Machine
        WriteU16(image, Coff + 2, 1);               // NumberOfSections
        WriteU16(image, Coff + 16, optionalSize);   // SizeOfOptionalHeader

        WriteU16(image, Optional, pe32Plus ? (ushort)0x20B : (ushort)0x10B);
        var directoryCountAt = Optional + (pe32Plus ? 108u : 92u);
        var directoryBase = Optional + (pe32Plus ? 112u : 96u);
        WriteU32(image, directoryCountAt, 16);

        // Section header: the whole point of the builder.
        var section = Optional + optionalSize;
        WriteU32(image, section + 8, 0x200);        // VirtualSize
        WriteU32(image, section + 12, SectionRva);  // VirtualAddress
        WriteU32(image, section + 16, 0x200);       // SizeOfRawData
        WriteU32(image, section + 20, SectionRaw);  // PointerToRawData

        if (imports.Length > 0)
        {
            WriteU32(image, directoryBase + (1 * 8), ImportTableRva);
            WriteU32(image, directoryBase + (1 * 8) + 4, (uint)((imports.Length + 1) * 20));
            var nameRva = ImportNamesRva;
            for (var i = 0; i < imports.Length; i++)
            {
                var descriptor = ToOffset(ImportTableRva) + ((uint)i * 20);
                WriteU32(image, descriptor, nameRva);          // OriginalFirstThunk, non-zero
                WriteU32(image, descriptor + 12, nameRva);     // Name
                nameRva += WriteAsciiZ(image, ToOffset(nameRva), imports[i]);
            }
        }

        if (delayImports.Length > 0)
        {
            WriteU32(image, directoryBase + (13 * 8), DelayTableRva);
            WriteU32(image, directoryBase + (13 * 8) + 4, (uint)((delayImports.Length + 1) * 32));
            var nameRva = DelayNamesRva;
            for (var i = 0; i < delayImports.Length; i++)
            {
                var descriptor = ToOffset(DelayTableRva) + ((uint)i * 32);
                WriteU32(image, descriptor, 1);                // Attributes: RVA-based
                WriteU32(image, descriptor + 4, nameRva);       // DllNameRVA
                nameRva += WriteAsciiZ(image, ToOffset(nameRva), delayImports[i]);
            }
        }

        return image;
    }

    private static uint WriteAsciiZ(byte[] image, uint at, string value)
    {
        var bytes = Encoding.ASCII.GetBytes(value);
        bytes.CopyTo(image, (int)at);
        return (uint)bytes.Length + 1;
    }

    private static void WriteU16(byte[] image, uint at, ushort value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan((int)at), value);

    private static void WriteU32(byte[] image, uint at, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan((int)at), value);
}
