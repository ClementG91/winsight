using System.Collections;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Xunit;

namespace WinSight.Response.Tests;

public sealed class JournalMetadataOwnershipTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-metadata-owner-").FullName;
    private string JournalPath => Path.Combine(_root, "history.jsonl");
    private string MetadataPath => JournalPath + ".evidence.json";
    public void Dispose() => Directory.Delete(_root, recursive: true);
    private static ActionJournalEntry Entry() => new(Guid.NewGuid(), ResponseActionKind.AddRule,
        ResponseOutcome.Succeeded, "retained action", DateTimeOffset.UtcNow, true);
    private static ResponseRule Rule() => new(Guid.NewGuid(), RuleScopeKind.Persistence,
        RuleDecision.Allow, RuleDuration.Permanent, DateTimeOffset.UtcNow, Item: "run:foreign-rule");

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ForeignRuleStoreAtMetadataPathIsPreserved(bool normalizedPath)
    {
        var path = normalizedPath ? Path.Combine(_root, ".", "history.jsonl") : JournalPath;
        var journal = new ActionJournal(path);
        var original = Entry();
        Assert.True(journal.TryAppend(original));
        var store = new RuleStore(MetadataPath);
        var rule = Rule();
        Assert.Equal(rule, store.Add(rule));
        var before = Directory.GetFiles(_root).ToDictionary(p => p, File.ReadAllBytes);
        Assert.Equal("EvidenceRecoveryBlocked", journal.TryAppendWithStatus(Entry()).Status.ToString());
        Assert.Equal("EvidenceRecoveryBlocked", journal.TryMarkUndone(original.ActionId, Guid.NewGuid()).Status.ToString());
        Assert.Equal(rule.Id, store.Match(RuleScopeKind.Persistence, item: rule.Item)?.Id);
        var snapshot = journal.ReadWithCoverage();
        Assert.False(snapshot.Unreadable);
        Assert.Equal(original.ActionId, Assert.Single(snapshot.Entries).ActionId);
        Assert.True(snapshot.EvidenceCountersUnknown);
        Assert.True(snapshot.EvidenceRecoveryPending);
        Assert.Equal(true, typeof(ActionJournalSnapshot).GetProperty("EvidenceMetadataUnrecognized")?.GetValue(snapshot));
        Assert.Equal(0, snapshot.DiscardedMetadataBytes);
        Assert.Null(snapshot.DiscardedMetadataTailSha256);
        Assert.Equal(before.Keys.Order(), Directory.GetFiles(_root).Order());
        Assert.All(before, item => Assert.Equal(item.Value, File.ReadAllBytes(item.Key)));
    }

    [Theory]
    [InlineData("interrupted")]
    [InlineData("empty")]
    [InlineData("version")]
    [InlineData("oversized")]
    [InlineData("future-field")]
    [InlineData("escaped-duplicate")]
    [InlineData("mistyped")]
    [InlineData("inactive-eviction-residue")]
    [InlineData("inactive-trim-residue")]
    [InlineData("partial-trim")]
    [InlineData("simultaneous-intents")]
    public void UnrecognizedMetadataNeverAuthorizesAnyWrite(string kind)
    {
        var journal = new ActionJournal(JournalPath);
        var original = Entry();
        Assert.True(journal.TryAppend(original));
        const string victim = "victim";
        File.WriteAllText(JournalPath + ".corrupt.jsonl", victim, new UTF8Encoding(false));
        var legacy = LegacyState();
        var metadata = kind switch
        {
            "interrupted" => "{ interrupted metadata",
            "empty" => "{}",
            "version" => legacy.Replace("\"Version\":1", "\"Version\":99", StringComparison.Ordinal),
            "oversized" => new string('m', 8193),
            "future-field" => legacy[..^1] + ",\"FutureIntent\":true}",
            "escaped-duplicate" => legacy[..^1] + ",\"\\u0056ersion\":1}",
            "mistyped" => legacy.Replace("\"DiscardedFiles\":0", "\"DiscardedFiles\":\"0\"", StringComparison.Ordinal),
            "inactive-eviction-residue" => legacy.Replace("\"PendingBytes\":0", "\"PendingBytes\":1", StringComparison.Ordinal),
            "inactive-trim-residue" => legacy[..^1] + TrimFields(-2, 0, 0, null, null),
            "partial-trim" => legacy[..^1] + ",\"PendingTrimSlot\":-2}",
            _ => JsonSerializer.Serialize(new
            {
                Version = 1,
                DiscardedBytes = 0L,
                DiscardedFiles = 0L,
                LossReason = "",
                PriorCountersUnknown = false,
                NextSlot = 0,
                PendingSlot = 0,
                PendingBytes = (long)Encoding.UTF8.GetByteCount(victim),
                PendingSha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(victim))),
                PendingTrimSlot = -1,
                PendingTrimBytes = 1L,
                PendingTrimLength = 16 * 1024 * 1024 + 1L,
                PendingTrimVolume = 1U,
                PendingTrimFileIndex = 1UL,
                PendingTrimTailSha256 = new string('A', 64),
                PendingTrimPublishedSha256 = new string('B', 64),
            }),
        };
        File.WriteAllText(MetadataPath, metadata, new UTF8Encoding(false));
        var before = Directory.GetFiles(_root).ToDictionary(p => p, File.ReadAllBytes);
        Assert.Equal("EvidenceRecoveryBlocked", journal.TryAppendWithStatus(Entry()).Status.ToString());
        Assert.Equal("EvidenceRecoveryBlocked", journal.TryMarkUndone(original.ActionId, Guid.NewGuid()).Status.ToString());
        var snapshot = journal.ReadWithCoverage();
        Assert.False(snapshot.Unreadable);
        Assert.Equal(original.ActionId, Assert.Single(snapshot.Entries).ActionId);
        Assert.True(snapshot.EvidenceCountersUnknown);
        Assert.Equal(0, snapshot.DiscardedMetadataBytes);
        Assert.Null(snapshot.DiscardedMetadataTailSha256);
        Assert.Equal(true, typeof(ActionJournalSnapshot).GetProperty("EvidenceMetadataUnrecognized")?.GetValue(snapshot));
        Assert.Equal(before.Keys.Order(), Directory.GetFiles(_root).Order());
        Assert.All(before, item => Assert.Equal(item.Value, File.ReadAllBytes(item.Key)));
    }

    [Fact]
    public void RecognizedLegacyNineFieldIntentResumesAndCountsExactlyOnce()
    {
        var journal = new ActionJournal(JournalPath);
        Assert.True(journal.TryAppend(Entry()));
        var victim = Encoding.UTF8.GetBytes("recognized victim");
        File.WriteAllBytes(JournalPath + ".corrupt.jsonl", victim);
        File.WriteAllText(MetadataPath, JsonSerializer.Serialize(new
        {
            Version = 1,
            DiscardedBytes = 3L,
            DiscardedFiles = 2L,
            LossReason = "evidence-budget",
            PriorCountersUnknown = false,
            NextSlot = 0,
            PendingSlot = 0,
            PendingBytes = (long)victim.Length,
            PendingSha256 = Convert.ToHexString(SHA256.HashData(victim)),
        }));
        var before = File.ReadAllBytes(MetadataPath);
        Assert.True(journal.ReadWithCoverage().EvidenceRecoveryPending);
        Assert.Equal(before, File.ReadAllBytes(MetadataPath));
        for (var pass = 0; pass < 2; pass++)
        {
            Assert.True(journal.TryAppend(Entry()));
            var snapshot = journal.ReadWithCoverage();
            Assert.Equal(3 + victim.Length, snapshot.DiscardedEvidenceBytes);
            Assert.Equal(3, snapshot.DiscardedEvidenceFiles);
            Assert.False(snapshot.EvidenceCountersUnknown);
            Assert.False(snapshot.EvidenceRecoveryPending);
            Assert.False(File.Exists(JournalPath + ".corrupt.jsonl"));
            Assert.DoesNotContain("IndexMissing", File.ReadAllText(MetadataPath), StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BothObservedMissingInitializersPreserveWhicheverPublishesFirst(bool indexFirst)
    {
        // Initialize the two private sidecars independently, then retain both actual writer
        // gates. Deterministic interleaving needs no timing, global hook or production test seam.
        using (WriterGate(JournalPath)) { }
        using (WriterGate(MetadataPath)) { }
        var store = new RuleStore(MetadataPath);
        var rule = Rule();
        byte[] winner;
        using (WriterGate(JournalPath))
        using (WriterGate(MetadataPath))
        {
            var load = typeof(RuleStore).GetMethods(BindingFlags.Instance | BindingFlags.NonPublic)
                .Single(method => method.Name == "TryLoadLocked" && method.GetParameters().Length == 2);
            object?[] loadArgs = [null, null];
            Assert.Equal(true, load.Invoke(store, loadArgs));
            Assert.Equal(RuleStoreStatus.Missing, Assert.IsType<RuleStoreResult>(loadArgs[1]).Status);
            var indexRead = typeof(ActionJournalEvidence).GetMethod("ReadState", BindingFlags.Static | BindingFlags.NonPublic)!;
            object?[] readArgs = [JournalPath, null, null];
            var state = indexRead.Invoke(null, readArgs)!;
            Assert.Equal(false, readArgs[1]);
            Assert.Equal(false, readArgs[2]);
            var missingProperty = state.GetType().GetProperty("IndexMissing");
            Assert.NotNull(missingProperty);
            Assert.Equal(true, missingProperty.GetValue(state));
            var indexSave = typeof(ActionJournalEvidence).GetMethod("Save", BindingFlags.Static | BindingFlags.NonPublic)!;
            Assert.True(indexSave.GetParameters()[1].ParameterType.IsByRef);
            var ruleSave = typeof(RuleStore).GetMethods(BindingFlags.Instance | BindingFlags.NonPublic)
                .SingleOrDefault(method => method.Name == "Save" && method.GetParameters().Length == 4);
            Assert.NotNull(ruleSave);
            var storedType = typeof(RuleStore).GetNestedType("StoredEntry", BindingFlags.NonPublic)!;
            var list = Assert.IsAssignableFrom<IList>(Activator.CreateInstance(typeof(List<>).MakeGenericType(storedType)));
            list.Add(Activator.CreateInstance(storedType, rule, default(ReadOnlyMemory<byte>)));
            object?[] saveArgs = [JournalPath, state];
            if (indexFirst)
            {
                Assert.Equal(true, indexSave.Invoke(null, saveArgs));
                Assert.Equal(false, missingProperty.GetValue(saveArgs[1]));
                winner = File.ReadAllBytes(MetadataPath);
                Assert.Equal(RuleStoreStatus.WriteFailed,
                    Assert.IsType<RuleStoreResult>(ruleSave.Invoke(store, [list, 0, 0, false])).Status);
            }
            else
            {
                Assert.Equal(RuleStoreStatus.Written,
                    Assert.IsType<RuleStoreResult>(ruleSave.Invoke(store, [list, 0, 0, false])).Status);
                winner = File.ReadAllBytes(MetadataPath);
                Assert.Equal(false, indexSave.Invoke(null, saveArgs));
                Assert.Equal(true, missingProperty.GetValue(saveArgs[1]));
            }
            Assert.Equal(winner, File.ReadAllBytes(MetadataPath));
            Assert.DoesNotContain(Directory.GetFiles(_root), p => p.EndsWith(".tmp", StringComparison.Ordinal));
        }
        Assert.Equal(winner, File.ReadAllBytes(MetadataPath));
        if (!indexFirst)
        {
            Assert.Equal(rule.Id, store.Match(RuleScopeKind.Persistence, item: rule.Item)?.Id);
            Assert.Equal("EvidenceRecoveryBlocked", new ActionJournal(JournalPath).TryAppendWithStatus(Entry()).Status.ToString());
            Assert.Equal(winner, File.ReadAllBytes(MetadataPath));
        }
        else
        {
            Assert.Null(store.Add(rule, out var result));
            Assert.Equal(RuleStoreStatus.InvalidFormat, result.Status);
            Assert.Equal(winner, File.ReadAllBytes(MetadataPath));
        }
    }

    private static string LegacyState() => JsonSerializer.Serialize(new
    {
        Version = 1,
        DiscardedBytes = 0L,
        DiscardedFiles = 0L,
        LossReason = "",
        PriorCountersUnknown = false,
        NextSlot = 0,
        PendingSlot = -1,
        PendingBytes = 0L,
        PendingSha256 = (string?)null,
    });

    private static IDisposable WriterGate(string path)
    {
        var type = typeof(ActionJournal).Assembly.GetType("WinSight.Response.ResponseFileLock");
        Assert.NotNull(type);
        var method = type.GetMethod("AcquireWriter", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        return Assert.IsAssignableFrom<IDisposable>(method.Invoke(null, [path, TimeSpan.FromSeconds(30)]));
    }

    private static string TrimFields(int slot, long bytes, long length, string? tail, string? published) =>
        ",\"PendingTrimSlot\":" + slot + ",\"PendingTrimBytes\":" + bytes + ",\"PendingTrimLength\":" + length
        + ",\"PendingTrimVolume\":1,\"PendingTrimFileIndex\":1,\"PendingTrimTailSha256\":"
        + JsonSerializer.Serialize(tail) + ",\"PendingTrimPublishedSha256\":" + JsonSerializer.Serialize(published) + "}";
}
