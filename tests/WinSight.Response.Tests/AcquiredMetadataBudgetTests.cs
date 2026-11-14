using System.Reflection;
using System.Text;

using WinSight.Core;

using Xunit;

namespace WinSight.Response.Tests;

public sealed class AcquiredMetadataBudgetTests : IDisposable
{
    private const string Legacy = """{"Version":1,"DiscardedBytes":0,"DiscardedFiles":0,"LossReason":"none","PriorCountersUnknown":false,"NextSlot":0,"PendingSlot":-1,"PendingBytes":0,"PendingSha256":null}""";
    private static readonly byte[] Bom = [0xef, 0xbb, 0xbf];
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-acquired-metadata-").FullName;
    private string MetadataPath => Path.Combine(_root, "history.jsonl.evidence.json");

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Theory]
    [InlineData(8193, false)]
    [InlineData(16552, false)]
    [InlineData(8193, true)]
    [InlineData(16552, true)]
    public void SameObjectGrowthCannotReuseCapturedLength(int physicalBytes, bool bom)
    {
        var original = Payload(0, bom);
        File.WriteAllBytes(MetadataPath, original);
        using var lease = AutomaticFileAccess.TryAcquire(MetadataPath, out var missing);
        Assert.NotNull(lease);
        Assert.False(missing);
        Assert.Equal(original.Length, lease.Length);
        Assert.True(lease.Length <= ActionJournalEvidence.MaxMetadataBytes);

        // The actual writer closes before opening DATA through the retained attributes lease.
        // A sharing/setup failure cannot stand in for the reader's size-budget assertion.
        File.AppendAllText(MetadataPath, new string(' ', physicalBytes - original.Length), new UTF8Encoding(false));
        var grown = File.ReadAllBytes(MetadataPath);
        Assert.Equal(physicalBytes, grown.Length);
        Assert.Equal(original.Length, lease.Length);
        Assert.True(lease.IsCurrent());
        using (var data = lease.OpenRead())
        {
            Assert.Equal(physicalBytes, data.Length);
        }

        var result = Read(lease);

        Assert.False(result.Unavailable);
        Assert.True(result.Invalid, "the existing acquired reader accepted DATA beyond the physical metadata budget");
        Assert.Equal("unrecognized-evidence-metadata", result.State.LossReason);
        Assert.True(result.State.PriorCountersUnknown);
        Assert.False(result.State.IndexMissing);
        Assert.Equal(grown, File.ReadAllBytes(MetadataPath));
    }

    [Theory]
    [InlineData(0, false, true)]
    [InlineData(0, true, true)]
    [InlineData(8192, false, true)]
    [InlineData(8192, true, true)]
    [InlineData(8193, false, false)]
    [InlineData(8193, true, false)]
    public void ExistingMetadataKeepsPhysicalByteAndBomBoundaries(int physicalBytes, bool bom, bool recognized)
    {
        var original = Payload(physicalBytes, bom);
        File.WriteAllBytes(MetadataPath, original);
        using var lease = AutomaticFileAccess.TryAcquire(MetadataPath);
        Assert.NotNull(lease);
        Assert.Equal(original.Length, lease.Length);

        var result = Read(lease);

        Assert.False(result.Unavailable);
        Assert.Equal(!recognized, result.Invalid);
        Assert.Equal(!recognized, result.State.PriorCountersUnknown);
        Assert.Equal(recognized ? "none" : "unrecognized-evidence-metadata", result.State.LossReason);
        Assert.False(result.State.IndexMissing);
        Assert.Equal(original, File.ReadAllBytes(MetadataPath));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ASecondOrNoninitialBomNeverMakesMetadataRecognized(bool secondBom)
    {
        byte[] original = secondBom
            ? [.. Bom, .. Bom, .. Encoding.UTF8.GetBytes(Legacy)]
            : [(byte)' ', .. Bom, .. Encoding.UTF8.GetBytes(Legacy)];
        File.WriteAllBytes(MetadataPath, original);
        using var lease = AutomaticFileAccess.TryAcquire(MetadataPath);
        Assert.NotNull(lease);

        var result = Read(lease);

        Assert.False(result.Unavailable);
        Assert.True(result.Invalid);
        Assert.True(result.State.PriorCountersUnknown);
        Assert.Equal("unrecognized-evidence-metadata", result.State.LossReason);
        Assert.Equal(original, File.ReadAllBytes(MetadataPath));
    }

    private static byte[] Payload(int physicalBytes, bool bom)
    {
        byte[] json = bom ? [.. Bom, .. Encoding.UTF8.GetBytes(Legacy)] : Encoding.UTF8.GetBytes(Legacy);
        if (physicalBytes == 0)
        {
            return json;
        }
        Assert.True(physicalBytes >= json.Length);
        var bytes = new byte[physicalBytes];
        json.CopyTo(bytes, 0);
        bytes.AsSpan(json.Length).Fill((byte)' ');
        return bytes;
    }

    private static (ActionJournalEvidence.State State, bool Unavailable, bool Invalid) Read(
        AutomaticFileAccess.LocalPathLease lease)
    {
        // This private boundary already exists and compiles in the preceding equivalent refactor.
        var method = typeof(ActionJournalEvidence).GetMethod("ReadAcquiredState", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        object?[] arguments = [lease, null, null];
        var state = Assert.IsType<ActionJournalEvidence.State>(method.Invoke(null, arguments));
        return (state, Assert.IsType<bool>(arguments[1]), Assert.IsType<bool>(arguments[2]));
    }
}
