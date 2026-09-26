using WinSight.Core;
using Xunit;

namespace WinSight.Core.Tests;

public sealed class AutomaticFileAccessTests
{
    [Theory]
    [InlineData(@"\\server\share\payload.dll")]
    [InlineData("//server/share/payload.dll")]
    [InlineData(@"\\?\UNC\server\share\payload.dll")]
    [InlineData(@"\??\UNC\server\share\payload.dll")]
    [InlineData(@"\Device\Mup\server\share\payload.dll")]
    public void NetworkAndDevicePathsAreRefused(string path) =>
        Assert.False(AutomaticFileAccess.IsLocal(path));

    [Fact]
    public void TheWindowsDirectoryIsLocal() =>
        Assert.True(AutomaticFileAccess.IsLocal(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows)));

    [Fact]
    public void ARelativePathStaysWithinTheLocalWorkingDirectory() =>
        Assert.True(AutomaticFileAccess.IsLocal(@"bin\tool.exe"));

    [Fact]
    public void ACompatibilityJunctionBelowTheSystemDriveIsRefused()
    {
        var systemRoot = Path.GetPathRoot(Environment.SystemDirectory)!;
        var junction = Path.Combine(systemRoot, "Documents and Settings");

        Assert.True((File.GetAttributes(junction) & FileAttributes.ReparsePoint) != 0);
        Assert.False(AutomaticFileAccess.IsLocal(junction));
        Assert.Null(AutomaticFileAccess.TryAcquire(junction));
        Assert.False(AutomaticFileAccess.DirectoryExists(junction));
    }

    [Fact]
    public void AReparseComponentInsideThePathIsRefusedWhenLinksAreAvailable()
    {
        var directory = Directory.CreateTempSubdirectory("winsight-reparse-").FullName;
        var target = Directory.CreateDirectory(Path.Combine(directory, "target")).FullName;
        var link = Path.Combine(directory, "link");
        var payload = Path.Combine(target, "payload.bin");
        File.WriteAllText(payload, "not followed");
        try
        {
            try
            {
                Directory.CreateSymbolicLink(link, target);
            }
            catch (Exception ex) when (ex is IOException
                                         or UnauthorizedAccessException
                                         or PlatformNotSupportedException
                                         or NotSupportedException)
            {
                return;
            }

            var redirected = Path.Combine(link, "payload.bin");
            Assert.True(AutomaticFileAccess.FileExists(payload));
            Assert.False(AutomaticFileAccess.IsLocal(redirected));
            Assert.Null(AutomaticFileAccess.TryAcquire(redirected));
            Assert.Null(AutomaticFileAccess.TryAcquireSharedRead(redirected));
            Assert.False(AutomaticFileAccess.FileExists(redirected));
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    [Fact]
    public void AnAcquiredFileIsReadByHandleAndDetectsAPathReplacement()
    {
        var directory = Directory.CreateTempSubdirectory("winsight-local-lease-").FullName;
        var path = Path.Combine(directory, "candidate.bin");
        var moved = Path.Combine(directory, "original.bin");
        File.WriteAllText(path, "ORIGINAL");
        try
        {
            using var lease = AutomaticFileAccess.TryAcquire(path);
            Assert.NotNull(lease);
            Assert.False(lease!.IsDirectory);
            Assert.Equal(8, lease.Length);
            Assert.True(lease.IsCurrent());

            // Current Windows can allow this rename despite an existing read-shared handle. The
            // lease therefore does not pretend sharing is an identity lock: it keeps the original
            // object readable by handle and detects that the path now names a replacement.
            File.Move(path, moved);
            File.WriteAllText(path, "REPLACED");

            Assert.False(lease.IsCurrent());
            using var stream = lease.OpenRead();
            using var reader = new StreamReader(stream);
            Assert.Equal("ORIGINAL", reader.ReadToEnd());
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    [Fact]
    public void AnOrdinaryFileCanBeAcquiredAndProbedWithoutAPathReopen()
    {
        var path = Path.Combine(Path.GetTempPath(), $"winsight-local-{Guid.NewGuid():N}.bin");
        File.WriteAllText(path, "content");
        try
        {
            Assert.True(AutomaticFileAccess.FileExists(path));
            Assert.False(AutomaticFileAccess.DirectoryExists(path));
            using var lease = AutomaticFileAccess.TryAcquire(path);
            using var stream = lease!.OpenRead();
            using var reader = new StreamReader(stream);
            Assert.Equal("content", reader.ReadToEnd());
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void SharedReadAcquiresTheExactObjectWhileAnotherHandleKeepsWriting()
    {
        var path = Path.Combine(Path.GetTempPath(), $"winsight-shared-{Guid.NewGuid():N}.bin");
        try
        {
            using var writer = new FileStream(
                path,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.ReadWrite | FileShare.Delete);
            writer.Write("FIRST"u8);
            writer.Flush();

            using var lease = AutomaticFileAccess.TryAcquireSharedRead(path);
            Assert.NotNull(lease);
            Assert.False(lease!.IsDirectory);

            writer.Write("SECOND"u8);
            writer.Flush();
            using var reader = lease.OpenRead();
            var content = new byte[11];
            reader.ReadExactly(content);
            Assert.Equal("FIRSTSECOND"u8.ToArray(), content);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void DeleteLeaseReadsAndDeletesTheSameOrdinaryFile()
    {
        var path = Path.Combine(Path.GetTempPath(), $"winsight-delete-{Guid.NewGuid():N}.bin");
        File.WriteAllText(path, "EXPECTED");
        try
        {
            var lease = AutomaticFileAccess.TryAcquireForDelete(path);
            Assert.NotNull(lease);
            using (var stream = lease!.OpenRead())
            using (var reader = new StreamReader(stream))
            {
                Assert.Equal("EXPECTED", reader.ReadToEnd());
            }

            Assert.True(lease.TryDelete());
            lease.Dispose();
            Assert.True(SpinWait.SpinUntil(() => !File.Exists(path), TimeSpan.FromSeconds(2)));
        }
        finally
        {
            try { File.Delete(path); }
            catch (IOException) { }
        }
    }

    [Fact]
    public void HandleRelativeMutationsCreateAppendReplaceAndDeleteAnOrdinaryFile()
    {
        var root = Directory.CreateTempSubdirectory("winsight-mutation-").FullName;
        var directory = Path.Combine(root, "one", "two");
        var path = Path.Combine(directory, "state.bin");
        try
        {
            Assert.True(AutomaticFileAccess.TryEnsureDirectory(directory));
            Assert.True(AutomaticFileAccess.TryCreateNewFile(path, "FIRST"u8));
            Assert.False(AutomaticFileAccess.TryCreateNewFile(path, "WRONG"u8));
            Assert.True(AutomaticFileAccess.TryAppendFile(path, "-SECOND"u8));
            Assert.Equal("FIRST-SECOND", File.ReadAllText(path));

            Assert.True(AutomaticFileAccess.TryWriteAtomic(path, "REPLACED"u8));
            Assert.Equal("REPLACED", File.ReadAllText(path));
            Assert.Empty(Directory.EnumerateFiles(directory, ".winsight-*.tmp"));

            Assert.True(AutomaticFileAccess.TryDeleteFile(path));
            Assert.True(SpinWait.SpinUntil(() => !File.Exists(path), TimeSpan.FromSeconds(2)));
        }
        finally
        {
            TryDeleteTree(root);
        }
    }

    [Fact]
    public void HandleRelativeMutationRefusesAReparseParentComponentWhenLinksAreAvailable()
    {
        var root = Directory.CreateTempSubdirectory("winsight-mutation-link-").FullName;
        var outside = Directory.CreateDirectory(Path.Combine(root, "outside")).FullName;
        var link = Path.Combine(root, "link");
        try
        {
            try
            {
                Directory.CreateSymbolicLink(link, outside);
            }
            catch (Exception ex) when (ex is IOException
                                         or UnauthorizedAccessException
                                         or PlatformNotSupportedException
                                         or NotSupportedException)
            {
                return;
            }

            var redirectedDirectory = Path.Combine(link, "nested");
            var redirectedFile = Path.Combine(redirectedDirectory, "state.bin");
            Assert.False(AutomaticFileAccess.TryEnsureDirectory(redirectedDirectory));
            Assert.False(AutomaticFileAccess.TryCreateNewFile(
                redirectedFile,
                "MUST NOT ESCAPE"u8,
                createParentDirectories: true));
            Assert.False(Directory.Exists(Path.Combine(outside, "nested")));
        }
        finally
        {
            TryDeleteTree(root);
        }
    }

    [Fact]
    public void AppendRefusesAReparseLeafWhenLinksAreAvailable()
    {
        var root = Directory.CreateTempSubdirectory("winsight-append-link-").FullName;
        var target = Path.Combine(root, "target.bin");
        var link = Path.Combine(root, "journal.bin");
        File.WriteAllText(target, "UNCHANGED");
        try
        {
            try
            {
                File.CreateSymbolicLink(link, target);
            }
            catch (Exception ex) when (ex is IOException
                                         or UnauthorizedAccessException
                                         or PlatformNotSupportedException
                                         or NotSupportedException)
            {
                return;
            }

            Assert.False(AutomaticFileAccess.TryAppendFile(link, "-ESCAPED"u8));
            Assert.Equal("UNCHANGED", File.ReadAllText(target));
        }
        finally
        {
            TryDeleteTree(root);
        }
    }

    [Fact]
    public void AtomicReplaceNeverWritesThroughAReparseLeafWhenLinksAreAvailable()
    {
        var root = Directory.CreateTempSubdirectory("winsight-replace-link-").FullName;
        var target = Path.Combine(root, "target.bin");
        var link = Path.Combine(root, "state.bin");
        File.WriteAllText(target, "UNCHANGED");
        try
        {
            try
            {
                File.CreateSymbolicLink(link, target);
            }
            catch (Exception ex) when (ex is IOException
                                         or UnauthorizedAccessException
                                         or PlatformNotSupportedException
                                         or NotSupportedException)
            {
                return;
            }

            var replaced = AutomaticFileAccess.TryWriteAtomic(link, "SAFE"u8);

            Assert.Equal("UNCHANGED", File.ReadAllText(target));
            if (replaced)
            {
                Assert.Equal("SAFE", File.ReadAllText(link));
                Assert.False(File.GetAttributes(link).HasFlag(FileAttributes.ReparsePoint));
            }
        }
        finally
        {
            TryDeleteTree(root);
        }
    }

    [Fact]
    public void SignatureVerificationDoesNotCallADelegateForARemotePath()
    {
        var inner = new CountingVerifier();
        var verifier = new CachingSignatureVerifier(inner);

        var verdict = verifier.Verify(@"\\server\share\payload.dll");

        Assert.Equal(SignatureState.Unknown, verdict.State);
        Assert.Equal(0, inner.Calls);
    }

    private sealed class CountingVerifier : ISignatureVerifier
    {
        public int Calls { get; private set; }

        public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default)
        {
            Calls++;
            return AutomaticFileAccess.IsLocal(path)
                ? SignatureVerdict.Unsigned
                : SignatureVerdict.Unknown;
        }

        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths,
            CancellationToken cancellationToken = default) =>
            paths.ToDictionary(
                path => path,
                path => Verify(path, cancellationToken),
                StringComparer.OrdinalIgnoreCase);
    }

    private static void TryDeleteTree(string path)
    {
        try { Directory.Delete(path, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
