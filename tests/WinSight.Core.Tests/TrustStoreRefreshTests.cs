using System.Security.Cryptography.X509Certificates;

using WinSight.Core;
using Xunit;

namespace WinSight.Core.Tests;

public sealed class TrustStoreRefreshTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("winsight-roots-tests-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private static UserInstalledRoots.RootSnapshot Snapshot(
        IReadOnlySet<string>? machine, IReadOnlySet<string>? user) =>
        UserInstalledRoots.ReadSnapshot(location => location == StoreLocation.LocalMachine ? machine : user);

    private static HashSet<string> Set(params string[] values) => new(values, StringComparer.OrdinalIgnoreCase);

    [Fact]
    public void AddedUserRootIsVisibleInNextSnapshotWithoutChangingPreviousSnapshot()
    {
        var machine = Set("machine");
        var user = Set("machine");
        var before = Snapshot(machine, user);
        user.Add("new-user-root");
        var after = Snapshot(machine, user);

        Assert.Empty(before.UserThumbprints);
        Assert.Contains("NEW-USER-ROOT", after.UserThumbprints);
        Assert.NotEqual(before.Version, after.Version);
        Assert.Equal(SignatureTrustAnchor.Unspecified,
            UserInstalledRoots.TrustAnchorFor("file", before, _ => "new-user-root"));
        Assert.Equal(SignatureTrustAnchor.UserInstalledRoot,
            UserInstalledRoots.TrustAnchorFor("file", after, _ => "new-user-root"));
    }

    [Fact]
    public void SnapshotVersionDoesNotDependOnEnumerationOrderOrThumbprintCase()
    {
        var a = Snapshot(Set("Aa", "BB"), Set("aa", "Bb", "cc"));
        var b = Snapshot(Set("bb", "aa"), Set("CC", "BB", "AA"));
        Assert.Equal(a.Version, b.Version);
    }

    [Fact]
    public void RemovingMachineRootChangesVersionEvenWhenUserOnlySetRemainsEmpty()
    {
        var before = Snapshot(Set("a", "b"), Set("a", "b"));
        var after = Snapshot(Set("b"), Set("b"));
        Assert.Empty(before.UserThumbprints);
        Assert.Empty(after.UserThumbprints);
        Assert.NotEqual(before.Version, after.Version);
    }

    [Fact]
    public void UnreadableStoreMakesNoAnchorClaimAndDiffersFromEmptyStore()
    {
        var unreadable = Snapshot(null, Set("user"));
        var empty = Snapshot(Set(), Set("user"));
        Assert.False(unreadable.IsComplete);
        Assert.Empty(unreadable.UserThumbprints);
        Assert.NotEqual(unreadable.Version, empty.Version);
        Assert.Equal(SignatureTrustAnchor.Unspecified,
            UserInstalledRoots.TrustAnchorFor("file", unreadable,
                _ => throw new InvalidOperationException("Incomplete snapshots must not classify a chain.")));
        Assert.Equal(SignatureTrustAnchor.UserInstalledRoot,
            UserInstalledRoots.TrustAnchorFor("file", empty, _ => "user"));
    }

    [Theory]
    [InlineData(null, SignatureTrustAnchor.Unspecified)]
    [InlineData("unknown", SignatureTrustAnchor.Unspecified)]
    [InlineData("machine", SignatureTrustAnchor.MachineRoot)]
    [InlineData("user", SignatureTrustAnchor.UserInstalledRoot)]
    public void AnchorRequiresObservedMembership(string? root, SignatureTrustAnchor expected)
    {
        var snapshot = Snapshot(Set("machine"), Set("machine", "user"));
        Assert.Equal(expected, UserInstalledRoots.TrustAnchorFor("file", snapshot, _ => root));
    }

    [Fact]
    public void CachedUnchangedFileIsReverifiedAfterRootsChange()
    {
        var path = Path.Combine(_directory, "unchanged.bin");
        File.WriteAllText(path, "unchanged-content");
        var snapshot = Snapshot(Set("machine"), Set("machine"));
        var inner = new CountingVerifier();
        var snapshotsRead = 0;
        var cache = new CachingSignatureVerifier(inner, () => { snapshotsRead++; return snapshot; });

        Assert.Equal(SignatureState.SignedUntrusted, cache.Verify(path).State);
        Assert.Equal(SignatureState.SignedUntrusted, cache.Verify(path).State);
        Assert.Equal(1, inner.Calls);

        snapshot = Snapshot(Set("machine"), Set("machine", "new-user"));
        inner.Current = new SignatureVerdict(SignatureState.SignedTrusted, "test", SignatureTrustAnchor.UserInstalledRoot);
        Assert.Equal(SignatureTrustAnchor.UserInstalledRoot, cache.Verify(path).Anchor);
        Assert.Equal(2, inner.Calls);
        Assert.Equal(3, snapshotsRead);

        snapshot = Snapshot(Set("machine"), Set("machine"));
        inner.Current = new SignatureVerdict(SignatureState.SignedUntrusted, "test");
        Assert.Equal(SignatureState.SignedUntrusted, cache.Verify(path).State);
        Assert.Equal(3, inner.Calls);
    }

    [Fact]
    public void UnreadableRootsInvalidateOldCacheAndDoNotCacheNewVerdicts()
    {
        var path = Path.Combine(_directory, "unreadable-store.bin");
        File.WriteAllText(path, "unchanged-content");
        var snapshot = Snapshot(Set("machine"), Set("machine"));
        var inner = new CountingVerifier();
        var cache = new CachingSignatureVerifier(inner, () => snapshot);
        _ = cache.Verify(path);

        snapshot = Snapshot(null, Set("machine"));
        _ = cache.Verify(path);
        _ = cache.Verify(path);
        Assert.Equal(3, inner.Calls);
    }

    private sealed class CountingVerifier : ISignatureVerifier
    {
        public int Calls { get; private set; }
        public SignatureVerdict Current { get; set; } = new(SignatureState.SignedUntrusted, "test");

        public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default) =>
            VerifyMany([path], cancellationToken)[path];

        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default)
        {
            Calls++;
            return paths.ToDictionary(path => path, _ => Current, StringComparer.OrdinalIgnoreCase);
        }
    }
}
