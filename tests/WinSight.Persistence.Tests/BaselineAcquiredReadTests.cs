using System.Reflection;
using System.Text;

using WinSight.Core;

using Xunit;

namespace WinSight.Persistence.Tests;

public sealed class BaselineAcquiredReadTests : IDisposable
{
    private const int Limit = 16 * 1024 * 1024;
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-acquired-baseline-").FullName;
    private string BaselinePath => Path.Combine(_root, "baseline.tsv");
    private static PersistenceIdentity Identity(string name) =>
        PersistenceIdentity.FromEntry(Entries.Signed(AutostartVector.RunKey, name, @"C:\toy.exe"));

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void GrowthBeyondPhysicalBudgetIsUnavailable()
    {
        var identity = Identity("Retained");
        new FilePersistenceBaselineStore(BaselinePath).Save([identity]);
        var prefix = File.ReadAllBytes(BaselinePath);
        using var lease = Acquire();
        var captured = lease.Length;
        Assert.True(captured < Limit);
        Assert.True(lease.TryGetExtendedIdentity(out var volume, out var low, out var high, out var created));
        using (var writer = new FileStream(BaselinePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
        {
            // A valid retained identity matters: an empty baseline plus one malformed line would
            // already return null and could not establish this regression.
            var padding = new byte[Limit + 1 - prefix.Length];
            padding.AsSpan().Fill((byte)' ');
            writer.Write(padding);
            writer.Flush(flushToDisk: true);
        }
        Assert.Equal(captured, lease.Length);
        Assert.True(lease.IsCurrent());
        using (var current = Acquire())
        {
            Assert.Equal(lease.Identity, current.Identity);
            Assert.True(current.TryGetExtendedIdentity(out var currentVolume, out var currentLow, out var currentHigh, out var currentCreated));
            Assert.Equal((volume, low, high, created), (currentVolume, currentLow, currentHigh, currentCreated));
        }
        using (var data = lease.OpenRead())
        {
            Assert.Equal(Limit + 1, data.Length);
        }

        var loaded = Read(lease);

        Assert.False(loaded is not null, "the complete physical baseline exceeds the existing 16 MiB read budget");
        Assert.Equal(Limit + 1, new FileInfo(BaselinePath).Length);
        using var preserved = File.OpenRead(BaselinePath);
        var retained = new byte[prefix.Length];
        preserved.ReadExactly(retained);
        Assert.Equal(prefix, retained);
    }

    [Theory]
    [InlineData(0, false, true)]
    [InlineData(0, true, true)]
    [InlineData(Limit, false, true)]
    [InlineData(Limit, true, true)]
    [InlineData(Limit + 1, false, false)]
    public void StablePhysicalAndBomBoundariesPreserveIdentityAndCoverage(int bytes, bool bom, bool readable)
    {
        var identity = Identity("Stable");
        var coverage = new PersistenceCoverageMap(new Dictionary<string, IReadOnlyList<string>> { ["ReviewedSource"] = [] });
        new FilePersistenceBaselineStore(BaselinePath).Save([identity], coverage);
        var prefix = File.ReadAllBytes(BaselinePath);
        if (bom)
        {
            prefix = [0xef, 0xbb, 0xbf, .. prefix];
        }
        var payload = new byte[bytes == 0 ? prefix.Length : bytes];
        prefix.CopyTo(payload, 0);
        // Save ends with a newline, so padding adds one ignored ordinary line. The valid identity
        // and actual recorded coverage must survive complete parsing of this bounded input.
        payload.AsSpan(prefix.Length).Fill((byte)' ');
        File.WriteAllBytes(BaselinePath, payload);
        using var lease = Acquire();

        var loaded = Read(lease);

        Assert.Equal(readable, loaded is not null);
        if (readable)
        {
            Assert.Equal(identity, Assert.Single(loaded!.Identities));
            Assert.Equal("ReviewedSource", Assert.Single(loaded.Coverage!.Sources).Key);
        }
        Assert.Equal(payload, File.ReadAllBytes(BaselinePath));
    }

    [Fact]
    public void InBudgetSameObjectGrowthLoadsTheAdditionalIdentity()
    {
        var first = Identity("First");
        var second = Identity("Second");
        new FilePersistenceBaselineStore(BaselinePath).Save([first]);
        var other = Path.Combine(_root, "other.tsv");
        new FilePersistenceBaselineStore(other).Save([second]);
        var extra = File.ReadAllLines(other, Encoding.UTF8)[1] + "\n";
        using var lease = Acquire();
        var captured = lease.Length;
        File.AppendAllText(BaselinePath, extra, new UTF8Encoding(false));
        Assert.Equal(captured, lease.Length);
        Assert.True(lease.IsCurrent());
        using (var data = lease.OpenRead())
        {
            Assert.Equal(captured + Encoding.UTF8.GetByteCount(extra), data.Length);
        }

        var loaded = Assert.IsType<PersistedBaseline>(Read(lease));

        Assert.Equal(2, loaded.Identities.Count);
        Assert.Contains(first, loaded.Identities);
        Assert.Contains(second, loaded.Identities);
    }

    [Fact]
    public void UnknownHeaderRemainsUnavailable()
    {
        File.WriteAllText(BaselinePath, "#unknown-baseline\n", new UTF8Encoding(false));
        using var lease = Acquire();

        Assert.Null(Read(lease));
    }

    private AutomaticFileAccess.LocalPathLease Acquire()
    {
        var lease = AutomaticFileAccess.TryAcquire(BaselinePath, out var missing);
        Assert.NotNull(lease);
        Assert.False(missing);
        Assert.True(lease.IsCurrent());
        return lease;
    }

    private static PersistedBaseline? Read(AutomaticFileAccess.LocalPathLease lease)
    {
        var method = typeof(FilePersistenceBaselineStore).GetMethod("ReadAcquiredBaseline", BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(method);
        var loaded = method.Invoke(null, [lease]);
        Assert.True(lease.IsCurrent());
        using var stillReadable = lease.OpenRead();
        Assert.True(stillReadable.CanRead);
        return loaded is null ? null : Assert.IsType<PersistedBaseline>(loaded);
    }
}
