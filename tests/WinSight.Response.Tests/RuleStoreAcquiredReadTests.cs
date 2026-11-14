using System.Reflection;
using System.Text;
using System.Text.Json;

using WinSight.Core;

using Xunit;

namespace WinSight.Response.Tests;

public sealed class RuleStoreAcquiredReadTests : IDisposable
{
    private const int Limit = 8 * 1024 * 1024;
    private const string Empty = """{"Version":1,"Rules":[]}""";
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-acquired-rules-").FullName;
    private string StorePath => Path.Combine(_root, "rules.json");

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void GrowthBeyondPhysicalLimitCannotLoadCapturedPrefix()
    {
        File.WriteAllText(StorePath, Empty, new UTF8Encoding(false));
        using var lease = Acquire();
        var originalLength = lease.Length;
        File.AppendAllText(StorePath, new string(' ', Limit + 1 - (int)originalLength), new UTF8Encoding(false));
        AssertGrowthPrerequisites(lease, originalLength, Limit + 1);

        var read = Read(lease);

        Assert.False(read.Loaded);
        Assert.Equal(RuleStoreStatus.ByteLimit, read.Result.Status);
        Assert.Empty(read.Rules);
        Assert.Equal(Limit + 1, new FileInfo(StorePath).Length);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InvalidSuffixCannotHideBehindCapturedValidRoot(bool invalidUtf8)
    {
        File.WriteAllText(StorePath, Empty, new UTF8Encoding(false));
        using var lease = Acquire();
        var originalLength = lease.Length;
        byte[] suffix = invalidUtf8 ? [0xff] : Encoding.UTF8.GetBytes("{}");
        using (var writer = new FileStream(StorePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
        {
            writer.Write(suffix);
            writer.Flush(flushToDisk: true);
        }
        AssertGrowthPrerequisites(lease, originalLength, originalLength + suffix.Length);

        var read = Read(lease);

        Assert.False(read.Loaded);
        Assert.Equal(RuleStoreStatus.InvalidJson, read.Result.Status);
        Assert.Empty(read.Rules);
    }

    [Fact]
    public void LongerValidSameObjectRootLoadsTheActualRule()
    {
        File.WriteAllText(StorePath, Empty, new UTF8Encoding(false));
        using var lease = Acquire();
        var originalLength = lease.Length;
        var rule = new ResponseRule(Guid.NewGuid(), RuleScopeKind.Persistence, RuleDecision.Allow,
            RuleDuration.Permanent, DateTimeOffset.UtcNow, Item: "run:actual-grown-rule");
        var actual = JsonSerializer.SerializeToUtf8Bytes(new { Version = 1, Rules = new[] { rule } });
        using (var writer = new FileStream(StorePath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
        {
            writer.Write(actual);
            writer.SetLength(actual.Length);
            writer.Flush(flushToDisk: true);
        }
        AssertGrowthPrerequisites(lease, originalLength, actual.Length);

        var read = Read(lease);

        Assert.True(read.Loaded);
        Assert.Equal(RuleStoreStatus.Loaded, read.Result.Status);
        Assert.Equal(rule, Assert.Single(read.Rules));
        Assert.Equal(actual, File.ReadAllBytes(StorePath));
    }

    [Fact]
    public void WhitespaceGrowthWithinLimitRemainsValid()
    {
        File.WriteAllText(StorePath, Empty, new UTF8Encoding(false));
        using var lease = Acquire();
        var originalLength = lease.Length;
        File.AppendAllText(StorePath, new string(' ', 4096), new UTF8Encoding(false));
        AssertGrowthPrerequisites(lease, originalLength, originalLength + 4096);

        var read = Read(lease);

        Assert.True(read.Loaded);
        Assert.Equal(RuleStoreStatus.Loaded, read.Result.Status);
        Assert.Empty(read.Rules);
    }

    [Theory]
    [InlineData(0, false, RuleStoreStatus.Loaded)]
    [InlineData(Limit, false, RuleStoreStatus.Loaded)]
    [InlineData(Limit + 1, false, RuleStoreStatus.ByteLimit)]
    [InlineData(0, true, RuleStoreStatus.InvalidJson)]
    public void StablePhysicalAndBomBoundariesRemainExplicit(int physicalBytes, bool bom, RuleStoreStatus expected)
    {
        byte[] prefix = bom ? [0xef, 0xbb, 0xbf, .. Encoding.UTF8.GetBytes(Empty)] : Encoding.UTF8.GetBytes(Empty);
        var bytes = new byte[physicalBytes == 0 ? prefix.Length : physicalBytes];
        prefix.CopyTo(bytes, 0);
        bytes.AsSpan(prefix.Length).Fill((byte)' ');
        File.WriteAllBytes(StorePath, bytes);
        using var lease = Acquire();

        var read = Read(lease);

        Assert.Equal(expected == RuleStoreStatus.Loaded, read.Loaded);
        Assert.Equal(expected, read.Result.Status);
        Assert.Empty(read.Rules);
        Assert.Equal(bytes, File.ReadAllBytes(StorePath));
    }

    [Theory]
    [InlineData("")]
    [InlineData("{broken")]
    public void IncompleteJsonIsNeverLoaded(string payload)
    {
        File.WriteAllText(StorePath, payload, new UTF8Encoding(false));
        using var lease = Acquire();

        var read = Read(lease);

        Assert.False(read.Loaded);
        Assert.Equal(RuleStoreStatus.InvalidJson, read.Result.Status);
        Assert.Empty(read.Rules);
    }

    private AutomaticFileAccess.LocalPathLease Acquire()
    {
        var lease = AutomaticFileAccess.TryAcquire(StorePath, out var missing);
        Assert.NotNull(lease);
        Assert.False(missing);
        Assert.True(lease.IsCurrent());
        return lease;
    }

    private void AssertGrowthPrerequisites(AutomaticFileAccess.LocalPathLease lease, long captured, long actual)
    {
        // Real native attributes lease; writer is closed before DATA is opened. No mocked stream,
        // absent helper, sharing failure or eventual retry can satisfy the behavioral oracle.
        Assert.True(actual > captured);
        Assert.Equal(captured, lease.Length);
        Assert.True(lease.IsCurrent());
        using var current = Acquire();
        Assert.Equal(lease.Identity, current.Identity);
        Assert.True(lease.TryGetExtendedIdentity(out var volume, out var low, out var high, out var created));
        Assert.True(current.TryGetExtendedIdentity(out var currentVolume, out var currentLow, out var currentHigh, out var currentCreated));
        Assert.Equal((volume, low, high, created), (currentVolume, currentLow, currentHigh, currentCreated));
        using var data = lease.OpenRead();
        Assert.Equal(actual, data.Length);
    }

    private static (bool Loaded, RuleStoreResult Result, ResponseRule[] Rules) Read(AutomaticFileAccess.LocalPathLease lease)
    {
        // Production's already-existing private boundary; no public test seam or replacement parser.
        var method = typeof(RuleStore).GetMethod("TryReadAcquiredRules", BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(method);
        object?[] arguments = [lease, null, null, 0, null];
        var loaded = Assert.IsType<bool>(method.Invoke(null, arguments));
        var result = Assert.IsType<RuleStoreResult>(arguments[2]);
        var entries = Assert.IsAssignableFrom<Array>(arguments[1]);
        var rules = entries.Cast<object>().Select(entry => Assert.IsType<ResponseRule>(
            entry.GetType().GetProperty("Rule")!.GetValue(entry))).ToArray();
        Assert.True(lease.IsCurrent()); // The helper borrows, and must not dispose, the native lease.
        using var stillReadable = lease.OpenRead();
        Assert.True(stillReadable.CanRead);
        return (loaded, result, rules);
    }
}
