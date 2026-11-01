using System.Reflection;

using WinSight.Core;

using Xunit;

namespace WinSight.Ransomware.Tests;

public sealed class CanaryAcquiredContentTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-acquired-canary-").FullName;
    private string CanaryPath => Path.Combine(_root, "decoy.xlsx");

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void GrowthAfterAcquisitionCannotHideSuffix()
    {
        var expected = CanaryDocument.For(".xlsx");
        File.WriteAllBytes(CanaryPath, expected);
        using var lease = AutomaticFileAccess.TryAcquire(CanaryPath, out var missing);
        Assert.NotNull(lease);
        Assert.False(missing);
        Assert.Equal(expected.Length, lease.Length);
        Assert.True(lease.TryGetExtendedIdentity(out var volume, out var low, out var high, out var created));
        using (var writer = new FileStream(CanaryPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
        {
            writer.WriteByte(0x5a);
            writer.Flush(flushToDisk: true);
        }

        Assert.Equal(expected.Length, lease.Length);
        Assert.True(lease.IsCurrent());
        using (var current = AutomaticFileAccess.TryAcquire(CanaryPath))
        {
            Assert.NotNull(current);
            Assert.Equal(lease.Identity, current.Identity);
            Assert.True(current.TryGetExtendedIdentity(out var currentVolume, out var currentLow, out var currentHigh, out var currentCreated));
            Assert.Equal((volume, low, high, created), (currentVolume, currentLow, currentHigh, currentCreated));
        }
        using (var data = lease.OpenRead())
        {
            Assert.Equal(expected.Length + 1, data.Length);
        }

        var intact = Matches(lease, expected);

        Assert.False(intact, "a pristine prefix with a real appended suffix is modified");
        Assert.Equal(expected.Length + 1, new FileInfo(CanaryPath).Length);
        Assert.Equal((byte)0x5a, File.ReadAllBytes(CanaryPath)[^1]);
    }

    [Theory]
    [InlineData(".xlsx", "pristine", true)]
    [InlineData(".docx", "pristine", true)]
    [InlineData(".xlsx", "rewrite", true)]
    [InlineData(".docx", "rewrite", true)]
    [InlineData(".xlsx", "modified", false)]
    [InlineData(".docx", "modified", false)]
    [InlineData(".xlsx", "truncated", false)]
    [InlineData(".docx", "truncated", false)]
    [InlineData(".xlsx", "suffix", false)]
    [InlineData(".docx", "suffix", false)]
    public void StableDocumentBoundariesRetainTheirMeaning(string extension, string change, bool expectedIntact)
    {
        var expected = CanaryDocument.For(extension);
        var originalExpected = expected.ToArray();
        var actual = expected.ToArray(); // Keep the canonical expected bytes unchanged.
        if (change == "modified")
        {
            actual[^1] ^= 0x5a;
        }
        else if (change == "truncated")
        {
            actual = actual[..^1];
        }
        else if (change == "suffix")
        {
            actual = [.. actual, 0x5a];
        }
        var path = Path.Combine(_root, "decoy" + extension);
        File.WriteAllBytes(path, actual);
        if (change == "rewrite")
        {
            File.WriteAllBytes(path, actual);
        }
        using var lease = AutomaticFileAccess.TryAcquire(path);
        Assert.NotNull(lease);

        Assert.Equal(expectedIntact, Matches(lease, expected));

        Assert.Equal(actual, File.ReadAllBytes(path));
        Assert.Equal(originalExpected, expected);
    }

    private static bool Matches(AutomaticFileAccess.LocalPathLease lease, byte[] expected)
    {
        // This production boundary already exists in the preceding signed equivalent extraction.
        var method = typeof(CanaryManager).GetMethod("ContentMatchesAcquiredCanary", BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(method);
        var intact = Assert.IsType<bool>(method.Invoke(null, [lease, expected]));
        Assert.True(lease.IsCurrent());
        using var stillReadable = lease.OpenRead();
        Assert.True(stillReadable.CanRead);
        return intact;
    }
}
