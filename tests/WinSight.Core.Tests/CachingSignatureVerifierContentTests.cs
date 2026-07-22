using WinSight.Core;

using Xunit;

namespace WinSight.Core.Tests;

/// <summary>
/// What the signature cache promises about a file that was swapped underneath it.
/// </summary>
/// <remarks>
/// The cheap fingerprint is length plus both timestamps, and all three are attacker-controlled:
/// restoring timestamps after overwriting a file is one API call (MITRE T1070.006). These tests
/// perform that swap for real on disk rather than asserting against a mock, because the whole
/// question is whether the filesystem metadata the cache reads can be made to lie.
/// </remarks>
public sealed class CachingSignatureVerifierContentTests : IDisposable
{
    private static readonly SignatureVerdict Trusted =
        new(SignatureState.SignedTrusted, "CN=WinSight Test Signer");

    private readonly string _directory =
        Directory.CreateTempSubdirectory("winsight-cache-tests").FullName;

    public void Dispose()
    {
        try { Directory.Delete(_directory, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    /// <summary>Counts calls so a cache hit is distinguishable from a re-verification.</summary>
    private sealed class CountingVerifier(SignatureVerdict verdict) : ISignatureVerifier
    {
        public int Calls { get; private set; }

        public SignatureVerdict Current { get; set; } = verdict;

        public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default)
            => VerifyMany([path], cancellationToken)[path];

        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default)
        {
            Calls++;
            return paths.ToDictionary(p => p, _ => Current, StringComparer.OrdinalIgnoreCase);
        }
    }

    /// <summary>Overwrites content while restoring every timestamp and keeping the length.</summary>
    private static void SwapPreservingMetadata(string path, string replacement)
    {
        var created = File.GetCreationTimeUtc(path);
        var written = File.GetLastWriteTimeUtc(path);
        var accessed = File.GetLastAccessTimeUtc(path);

        File.WriteAllText(path, replacement);

        File.SetCreationTimeUtc(path, created);
        File.SetLastWriteTimeUtc(path, written);
        File.SetLastAccessTimeUtc(path, accessed);
    }

    private string WriteFile(string name, string content)
    {
        var path = Path.Combine(_directory, name);
        File.WriteAllText(path, content);
        return path;
    }

    // The window, demonstrated rather than described. This is the documented default behaviour;
    // if it ever changes, the remarks on CachingSignatureVerifier are wrong and must change too.
    [Fact]
    public void MetadataMode_ServesTheOldVerdictAfterATimestompedSwap()
    {
        var path = WriteFile("metadata.bin", "SIGNED-ORIGINAL");
        var inner = new CountingVerifier(Trusted);
        var cache = new CachingSignatureVerifier(inner);

        Assert.Equal(Trusted, cache.Verify(path));

        // Same length, timestamps restored: the metadata fingerprint cannot see this.
        SwapPreservingMetadata(path, "UNSIGNED-EVIL!!");
        inner.Current = SignatureVerdict.Unsigned;

        Assert.Equal(Trusted, cache.Verify(path));
        Assert.Equal(1, inner.Calls);
    }

    // The same swap against the mode a long-lived host uses.
    [Fact]
    public void ContentMode_RefusesToServeAVerdictForContentItNeverSaw()
    {
        var path = WriteFile("content.bin", "SIGNED-ORIGINAL");
        var inner = new CountingVerifier(Trusted);
        var cache = new CachingSignatureVerifier(inner, verifyContent: true);

        Assert.Equal(Trusted, cache.Verify(path));

        SwapPreservingMetadata(path, "UNSIGNED-EVIL!!");
        inner.Current = SignatureVerdict.Unsigned;

        Assert.Equal(SignatureVerdict.Unsigned, cache.Verify(path));
        Assert.Equal(2, inner.Calls);
    }

    // Content mode must still be a cache, or it would have traded a real cost for nothing.
    [Fact]
    public void ContentMode_StillServesAnUnchangedFileFromCache()
    {
        var path = WriteFile("stable.bin", "SIGNED-ORIGINAL");
        var inner = new CountingVerifier(Trusted);
        var cache = new CachingSignatureVerifier(inner, verifyContent: true);

        Assert.Equal(Trusted, cache.Verify(path));
        Assert.Equal(Trusted, cache.Verify(path));

        Assert.Equal(1, inner.Calls);
    }

    // A length change is visible to both modes; this guards the cheap path's floor.
    [Fact]
    public void MetadataMode_StillNoticesALengthChange()
    {
        var path = WriteFile("grow.bin", "SHORT");
        var inner = new CountingVerifier(Trusted);
        var cache = new CachingSignatureVerifier(inner);

        Assert.Equal(Trusted, cache.Verify(path));

        var created = File.GetCreationTimeUtc(path);
        var written = File.GetLastWriteTimeUtc(path);
        File.WriteAllText(path, "MUCH LONGER CONTENT");
        File.SetCreationTimeUtc(path, created);
        File.SetLastWriteTimeUtc(path, written);
        inner.Current = SignatureVerdict.Unsigned;

        Assert.Equal(SignatureVerdict.Unsigned, cache.Verify(path));
    }
}
