using System.Runtime.InteropServices;

using WinSight.FirewallService;

using Xunit;

namespace WinSight.FirewallService.Tests;

/// <summary>
/// The empirical ground the path-trust TOCTOU defence stands on: a real filesystem identity.
/// </summary>
/// <remarks>
/// <b>What this closes.</b> The Revalidate logic is thoroughly tested against a scripted metadata
/// source — it catches an identity change, an owner flip, a widened ACL, a reparse point, a
/// file/directory type swap and a topology change. The native identity query is ABI-sensitive, so
/// these tests pin the managed FILE_ID_INFO contract as well as exercising real simultaneous files
/// and the rename-aside/plant swap that must be detected.
///
/// These run against real temp files and need no elevation, so they are automated in CI rather than
/// left to a manual VM pass. They exercise <see cref="WindowsPathMetadataSource"/> directly — the
/// primitive Revalidate is built on — performing the classic rename-aside-then-plant swap.
/// </remarks>
public sealed class RealPathIdentityTests : IDisposable
{
    private readonly WindowsPathMetadataSource _source = new();
    private readonly string _dir =
        Directory.CreateTempSubdirectory("winsight-toctou").FullName;

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private string Identity(string path) => _source.Read(_source.Canonicalize(path)).StableIdentity;

    // ---- Stability: the same file reads the same identity every time --------------------------

    [Fact]
    public void TheSameUnchangedFileHasAStableIdentityAcrossReads()
    {
        var path = Path.Combine(_dir, "service.exe");
        File.WriteAllBytes(path, [1, 2, 3, 4]);

        var first = Identity(path);
        var second = Identity(path);

        Assert.False(string.IsNullOrWhiteSpace(first));
        Assert.Equal(first, second);
    }

    [Fact]
    public void FileIdInfoHasTheWindowsAbiSizeAndOffsets()
    {
        Assert.Equal(24, Marshal.SizeOf<FileIdInfo>());
        Assert.Equal(IntPtr.Zero, Marshal.OffsetOf<FileIdInfo>(nameof(FileIdInfo.VolumeSerialNumber)));
        Assert.Equal(new IntPtr(8), Marshal.OffsetOf<FileIdInfo>(nameof(FileIdInfo.FileId)));
    }

    [Fact]
    public void FileIdInfoCarriesAll128BitsOfTheNativeFileIdentifier()
    {
        Assert.Equal(16, Marshal.SizeOf<FileId128>());
        Assert.Equal(IntPtr.Zero, Marshal.OffsetOf<FileId128>(nameof(FileId128.Part0)));
        Assert.Equal(new IntPtr(8), Marshal.OffsetOf<FileId128>(nameof(FileId128.Part1)));
    }

    [Fact]
    public void StableIdentityFormatsVolumeAndBothFileIdHalvesInNativeOrder()
    {
        var identity = new FileIdInfo
        {
            VolumeSerialNumber = 0x0102030405060708,
            FileId = new FileId128 { Part0 = 0x1112131415161718, Part1 = 0x2122232425262728 },
        };

        Assert.Equal("0102030405060708:11121314151617182122232425262728",
            WindowsPathMetadataSource.FormatStableIdentity(identity));
        Assert.NotEqual(WindowsPathMetadataSource.FormatStableIdentity(identity),
            WindowsPathMetadataSource.FormatStableIdentity(new FileIdInfo
            {
                VolumeSerialNumber = 0,
                FileId = identity.FileId,
            }));
        Assert.NotEqual(WindowsPathMetadataSource.FormatStableIdentity(identity),
            WindowsPathMetadataSource.FormatStableIdentity(new FileIdInfo
            {
                VolumeSerialNumber = identity.VolumeSerialNumber,
                FileId = new() { Part0 = 0, Part1 = identity.FileId.Part1 },
            }));
        Assert.NotEqual(WindowsPathMetadataSource.FormatStableIdentity(identity),
            WindowsPathMetadataSource.FormatStableIdentity(new FileIdInfo
            {
                VolumeSerialNumber = identity.VolumeSerialNumber,
                FileId = new() { Part0 = identity.FileId.Part0, Part1 = 0 },
            }));
    }

    [Fact]
    public void EditingAFileInPlaceDoesNotChangeItsIdentity()
    {
        // The defence must not false-positive on the file merely being written to: only a *swap*
        // (a different file object at the same path) is an attack. An in-place overwrite keeps the
        // NTFS index, so a legitimate update by a trusted writer is not mistaken for a swap.
        var path = Path.Combine(_dir, "service.exe");
        File.WriteAllBytes(path, [1, 2, 3, 4]);
        var before = Identity(path);

        File.WriteAllBytes(path, Enumerable.Range(0, 5000).Select(i => (byte)i).ToArray());

        Assert.Equal(before, Identity(path));
    }

    // ---- The attack: a swapped file is a different identity -----------------------------------

    /// <summary>
    /// The classic TOCTOU swap: rename the trusted binary aside, drop a hostile one in its place.
    /// </summary>
    /// <remarks>
    /// An attacker with write access to the directory does not delete the original — they move it
    /// aside (so nothing notices it vanished) and plant their file at the exact path that was
    /// inspected. Same name, same size if they wish, different file object. The identity must differ,
    /// or Revalidate would accept the planted binary as the one it inspected.
    /// </remarks>
    [Fact]
    public void RenamingTheOriginalAsideAndPlantingANewFileChangesTheIdentity()
    {
        var path = Path.Combine(_dir, "service.exe");
        File.WriteAllBytes(path, [1, 2, 3, 4]);
        var inspected = Identity(path);

        File.Move(path, Path.Combine(_dir, "service.exe.bak"));
        File.WriteAllBytes(path, [1, 2, 3, 4]);   // the planted file

        Assert.NotEqual(inspected, Identity(path));
    }

    [Fact]
    public void TwoDifferentFilesHaveDifferentIdentities()
    {
        var a = Path.Combine(_dir, "a.exe");
        var b = Path.Combine(_dir, "b.exe");
        File.WriteAllBytes(a, [1]);
        File.WriteAllBytes(b, [1]);

        Assert.NotEqual(Identity(a), Identity(b));
    }

    // ---- The primitive Revalidate walks: the real ancestor chain ------------------------------

    [Fact]
    public void ExistingComponentsReturnsTheRealAncestorChainRootFirst()
    {
        var nested = Path.Combine(_dir, "sub", "service.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(nested)!);
        File.WriteAllBytes(nested, [1]);

        var components = _source.ExistingComponents(_source.Canonicalize(nested));

        // Root first, leaf last, and every link present so Revalidate can bind each one.
        Assert.Equal(_source.Canonicalize(nested), components[^1]);
        Assert.Contains(_source.Canonicalize(_dir), components);
        Assert.Contains(_source.Canonicalize(Path.Combine(_dir, "sub")), components);
        Assert.True(components.Count >= 3);
    }

    [Fact]
    public void ReadDistinguishesAFileFromADirectory()
    {
        var file = Path.Combine(_dir, "service.exe");
        File.WriteAllBytes(file, [1]);

        Assert.False(_source.Read(_source.Canonicalize(file)).IsDirectory);
        Assert.True(_source.Read(_source.Canonicalize(_dir)).IsDirectory);
    }

    [Fact]
    public void ReadReportsOwnerAndAccessRulesForARealFile()
    {
        // Revalidate re-evaluates the policy on the fresh metadata, so the metadata must actually
        // carry an owner and rules — an empty read would make every revalidation fail closed on a
        // real machine even when nothing was tampered with.
        var path = Path.Combine(_dir, "service.exe");
        File.WriteAllBytes(path, [1]);

        var metadata = _source.Read(_source.Canonicalize(path));

        Assert.True(metadata.Exists);
        Assert.False(string.IsNullOrWhiteSpace(metadata.OwnerSid));
        Assert.NotNull(metadata.AccessRules);
        Assert.NotEmpty(metadata.AccessRules);
    }
}
