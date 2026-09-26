using System.Diagnostics;

using WinSight.Core;

using Xunit;

namespace WinSight.Core.Tests;

/// <summary>
/// The compiled-in name is read from the image's own version resource, through the handle
/// WinSight acquired, and never from a language file or a download.
/// </summary>
public sealed class VersionResourceTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"winsight-version-{Guid.NewGuid():N}");

    public VersionResourceTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        foreach (var file in Directory.EnumerateFiles(_directory))
        {
            File.SetAttributes(file, FileAttributes.Normal);
        }
        Directory.Delete(_directory, recursive: true);
    }

    // WS-74. FileVersionInfo took the name from en-US\cmd.exe.mui and answered "Cmd.Exe.MUI", which
    // is in no interpreter table. The image's own resource names the program.
    [Theory]
    [InlineData(@"System32\cmd.exe")]
    [InlineData(@"System32\WindowsPowerShell\v1.0\powershell.exe")]
    [InlineData(@"System32\rundll32.exe")]
    public void AWindowsImageIsNamedByItsOwnResourceNotItsLanguageFile(string relative)
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), relative);
        using var lease = AutomaticFileAccess.TryAcquire(path);
        Assert.NotNull(lease);

        var name = VersionResource.ReadOriginalFileName(lease);

        Assert.NotNull(name);
        Assert.False(name.EndsWith(".mui", StringComparison.OrdinalIgnoreCase), name);
        Assert.Equal(Path.GetFileName(path), name, ignoreCase: true);
        // The platform reader names the language file; the program is the same.
        var platform = FileVersionInfo.GetVersionInfo(path).OriginalFilename ?? string.Empty;
        Assert.StartsWith(name, platform, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TheTableTheFileDeclaresComesFirst()
    {
        var info = PeResourceImage.VersionInfo(
            "040C04B0",
            ("040904B0", [("OriginalFilename", "english.exe")]),
            ("040C04B0", [("OriginalFilename", "french.exe")]));

        Assert.Equal("french.exe", VersionResource.OriginalFileName(info));
    }

    [Fact]
    public void WithoutTheDeclaredTableUsEnglishIsTriedAsWindowsDoes()
    {
        var info = PeResourceImage.VersionInfo(
            "041D04B0",
            ("080904B0", [("OriginalFilename", "british.exe")]),
            ("040904E4", [("OriginalFilename", "american.exe")]));

        Assert.Equal("american.exe", VersionResource.OriginalFileName(info));
    }

    [Fact]
    public void ATableNoRuleNamesIsStillRead()
    {
        var info = PeResourceImage.VersionInfo(
            translation: null,
            ("080904B0", [("CompanyName", "Contoso"), ("OriginalFilename", "british.exe")]));

        Assert.Equal("british.exe", VersionResource.OriginalFileName(info));
    }

    [Fact]
    public void ATableWithoutTheNameGivesWayToOneWithIt()
    {
        var info = PeResourceImage.VersionInfo(
            "040904B0",
            ("040904B0", [("CompanyName", "Contoso")]),
            ("080904B0", [("OriginalFilename", "british.exe")]));

        Assert.Equal("british.exe", VersionResource.OriginalFileName(info));
    }

    [Fact]
    public void ABlockThatIsNotAVersionResourceHasNoName()
    {
        var info = PeResourceImage.Block("SOMETHING_ELSE", 0, new byte[52], 52);

        Assert.Null(VersionResource.OriginalFileName(info));
    }

    // Hostile input: a truncated or corrupted resource yields a name or null, never an exception or
    // a read outside the buffer.
    [Fact]
    public void EveryTruncationAndEveryCorruptedByteIsSurvived()
    {
        var info = PeResourceImage.VersionInfo(
            "040904B0", ("040904B0", [("CompanyName", "Contoso"), ("OriginalFilename", "agent.exe")]));

        for (var length = 0; length < info.Length; length++)
        {
            _ = VersionResource.OriginalFileName(info.AsSpan(0, length));
        }
        for (var at = 0; at < info.Length; at++)
        {
            foreach (var value in new byte[] { 0x00, 0xFF, 0x7F })
            {
                var corrupted = (byte[])info.Clone();
                corrupted[at] = value;
                _ = VersionResource.OriginalFileName(corrupted);
            }
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TheResourceIsFoundInBothImageShapes(bool pe32Plus)
    {
        var image = PeResourceImage.Build(
            [
                (PeResources.ManifestType, 1, "<assembly/>"u8.ToArray()),
                (PeResources.VersionType, 1, PeResourceImage.VersionInfo("040904B0", ("040904B0", [("OriginalFilename", "agent.exe")]))),
            ],
            pe32Plus);

        using var stream = new MemoryStream(image);
        var data = PeResources.Read(stream, PeResources.VersionType, 1, ushort.MaxValue);

        Assert.NotNull(data);
        Assert.Equal("agent.exe", VersionResource.OriginalFileName(data));
        Assert.Equal("<assembly/>"u8.ToArray(), PeResources.Read(stream, PeResources.ManifestType, 1, 1024));
        Assert.Null(PeResources.Read(stream, PeResources.ManifestType, 2, 1024));
    }

    [Fact]
    public void AResourceLargerThanTheCapIsRefusedNotTruncated()
    {
        var image = PeResourceImage.Build([(PeResources.ManifestType, 1, new byte[4096])]);

        using var stream = new MemoryStream(image);

        Assert.Null(PeResources.Read(stream, PeResources.ManifestType, 1, 4095));
        Assert.Equal(4096, PeResources.Read(stream, PeResources.ManifestType, 1, 4096)?.Length);
    }

    // A directory whose entry points back at the root: the walk has a fixed depth and ends.
    [Fact]
    public void ADirectoryPointingAtItselfEndsTheWalk()
    {
        var image = PeResourceImage.Build([(PeResources.VersionType, 1, new byte[64])]);
        // The root's only entry (type 16) now names the root itself as its subdirectory, and the
        // root holds no entry 1, so the name level cannot be found.
        PeResourceImage.WriteU32(image, (uint)PeResourceImage.TreeOffset(16 + 4), 0x8000_0000);

        using var stream = new MemoryStream(image);

        Assert.Null(PeResources.Read(stream, PeResources.VersionType, 1, ushort.MaxValue));
    }

    [Fact]
    public void AResourceOutsideEverySectionIsNotRead()
    {
        var image = PeResourceImage.Build([(PeResources.VersionType, 1, new byte[64])]);
        // Point the data entry's RVA beyond the section.
        var entry = FindDataEntry(image);
        PeResourceImage.WriteU32(image, (uint)entry, 0x7000_0000);

        using var stream = new MemoryStream(image);

        Assert.Null(PeResources.Read(stream, PeResources.VersionType, 1, ushort.MaxValue));
    }

    [Fact]
    public void EveryTruncationOfTheImageIsSurvived()
    {
        var image = PeResourceImage.Build(
            [(PeResources.VersionType, 1, PeResourceImage.VersionInfo("040904B0", ("040904B0", [("OriginalFilename", "agent.exe")])))]);

        for (var length = 0; length < image.Length; length += 7)
        {
            using var stream = new MemoryStream(image, 0, length);
            var data = PeResources.Read(stream, PeResources.VersionType, 1, ushort.MaxValue);
            Assert.True(data is null || VersionResource.OriginalFileName(data) is null or "agent.exe");
        }
    }

    [Fact]
    public void NotAPeImageHasNoResource()
    {
        using var stream = new MemoryStream("MZ this is not an image"u8.ToArray());

        Assert.Null(PeResources.Read(stream, PeResources.VersionType, 1, ushort.MaxValue));
    }

    // RA-02 / WS-40: a file whose data is not on this machine is not read at all, so a cloud
    // provider is never asked for it. The same bytes, local, are read.
    [Fact]
    public void AFileWhoseDataIsNotLocalIsNotRead()
    {
        var path = Path.Combine(_directory, "agent.exe");
        File.WriteAllBytes(path, PeResourceImage.Build(
            [(PeResources.VersionType, 1, PeResourceImage.VersionInfo("040904B0", ("040904B0", [("OriginalFilename", "agent.exe")])))]));

        using (var local = AutomaticFileAccess.TryAcquire(path))
        {
            Assert.Equal("agent.exe", VersionResource.ReadOriginalFileName(local!));
        }

        File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.Offline);
        using var offline = AutomaticFileAccess.TryAcquire(path);

        Assert.NotNull(offline);
        Assert.False(offline.DataIsLocal);
        Assert.Null(VersionResource.ReadOriginalFileName(offline));
    }

    private static int FindDataEntry(byte[] image)
    {
        // Root (16 + 8), type directory (16 + 8), name directory (16 + 8), then the data entry.
        return PeResourceImage.TreeOffset(24 + 24 + 24);
    }
}
