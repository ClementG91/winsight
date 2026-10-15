using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using Microsoft.Win32;

using WinSight.Application;
using WinSight.Response;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class QuarantineEnvelopeRegressionTests
{
    [Theory]
    [InlineData("empty")]
    [InlineData("missing-target")]
    [InlineData("missing-payload")]
    [InlineData("null-target")]
    [InlineData("null-payload")]
    [InlineData("missing-kind")]
    [InlineData("missing-privilege")]
    [InlineData("null-label")]
    [InlineData("null-token")]
    [InlineData("unknown-kind")]
    [InlineData("unknown-privilege")]
    [InlineData("missing-hive")]
    [InlineData("missing-subkey")]
    [InlineData("missing-value")]
    [InlineData("empty-subkey")]
    [InlineData("missing-file")]
    [InlineData("relative-file")]
    public void MalformedEnvelopeIsRefusedAndAuditedWithoutDispatch(string shape)
    {
        var startup = shape is "missing-file" or "relative-file";
        var document = Envelope(startup ? StartupTarget() : RegistryTarget(), [1]);
        var target = document["Target"]!.AsObject();
        switch (shape)
        {
            case "empty": document.Clear(); break;
            case "missing-target": document.Remove("Target"); break;
            case "missing-payload": document.Remove("Payload"); break;
            case "null-target": document["Target"] = null; break;
            case "null-payload": document["Payload"] = null; break;
            case "missing-kind": target.Remove("Kind"); break;
            case "missing-privilege": target.Remove("Privilege"); break;
            case "null-label": target["DisplayName"] = null; break;
            case "null-token": target["RevalidationToken"] = null; break;
            case "unknown-kind": target["Kind"] = 999; break;
            case "unknown-privilege": target["Privilege"] = 999; break;
            case "missing-hive": target["Hive"] = null; break;
            case "missing-subkey": target["SubKey"] = null; break;
            case "missing-value": target["ValueName"] = null; break;
            case "empty-subkey": target["SubKey"] = ""; break;
            case "missing-file": target["FilePath"] = null; break;
            case "relative-file": target["FilePath"] = @"relative\startup.exe"; break;
        }
        var bytes = Encoding.UTF8.GetBytes(document.ToJsonString());
        using var fixture = new Fixture(bytes, startup ? QuarantineItemKind.File : QuarantineItemKind.RegistryValue);
        var mutator = new RecordingMutator();
        var responder = new PersistenceResponder(mutator, fixture.Quarantine, fixture.Journal);

        var result = responder.Restore(fixture.BlockId);

        Assert.Equal(ResponseOutcome.Failed, result.Outcome);
        Assert.Equal(0, mutator.Calls);
        Assert.Equal(bytes, fixture.Quarantine.ReadPayload(fixture.Item));
        Assert.Equal(fixture.Item, Assert.Single(fixture.Quarantine.List()));
        fixture.AssertCompleted(result, ResponseOutcome.Failed);
    }

    [Fact]
    public void RealMutatorEmptyEnvelopeProducesAnAuditedFailureInsteadOfAnException()
    {
        using var fixture = new Fixture(Encoding.UTF8.GetBytes("{}"));
        var responder = new PersistenceResponder(new RegistryAndFilePersistenceMutator(), fixture.Quarantine, fixture.Journal);
        ResponseResult? result = null;

        var exception = Record.Exception(() => result = responder.Restore(fixture.BlockId));

        Assert.Null(exception);
        Assert.NotNull(result);
        Assert.Equal(ResponseOutcome.Failed, result.Outcome);
        Assert.Equal(Encoding.UTF8.GetBytes("{}"), fixture.Quarantine.ReadPayload(fixture.Item));
        fixture.AssertCompleted(result, ResponseOutcome.Failed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ValidEnvelopeStillDispatchesIncludingEmptyPayload(bool startup)
    {
        var target = startup ? StartupTarget() : RegistryTarget() with { ValueName = "" };
        byte[] payload = startup ? [] : [1, 2, 3];
        using var fixture = new Fixture(JsonSerializer.SerializeToUtf8Bytes(new { Target = target, Payload = payload }),
            startup ? QuarantineItemKind.File : QuarantineItemKind.RegistryValue);
        var mutator = new RecordingMutator();
        var responder = new PersistenceResponder(mutator, fixture.Quarantine, fixture.Journal);

        var result = responder.Restore(fixture.BlockId);

        Assert.Equal(ResponseOutcome.Succeeded, result.Outcome);
        Assert.Equal(1, mutator.Calls);
        Assert.Equal(target, mutator.Target);
        Assert.Equal(payload, mutator.Payload);
        Assert.Empty(fixture.Quarantine.List());
        fixture.AssertCompleted(result, ResponseOutcome.Succeeded);
    }

    [Fact]
    public void ServiceTierEnvelopeRemainsUnsupportedWithoutDispatchOrPayloadDeletion()
    {
        var target = RegistryTarget() with { Privilege = ResponsePrivilege.Service, Hive = RegistryHive.LocalMachine };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new { Target = target, Payload = new byte[] { 1 } });
        using var fixture = new Fixture(bytes);
        var mutator = new RecordingMutator();

        var result = new PersistenceResponder(mutator, fixture.Quarantine, fixture.Journal).Restore(fixture.BlockId);

        Assert.Equal(ResponseOutcome.NotSupported, result.Outcome);
        Assert.Equal(0, mutator.Calls);
        Assert.Equal(bytes, fixture.Quarantine.ReadPayload(fixture.Item));
        fixture.AssertCompleted(result, ResponseOutcome.NotSupported);
    }

    private static JsonObject Envelope(PersistenceActionTarget target, byte[] payload) =>
        JsonSerializer.SerializeToNode(new { Target = target, Payload = payload })!.AsObject();

    private static PersistenceActionTarget RegistryTarget() => new(
        PersistenceActionKind.RegistryValue, ResponsePrivilege.CurrentUser, "synthetic entry",
        RegistryHive.CurrentUser, @"Software\WinSightSyntheticEnvelope", "Value", null, "synthetic token");

    private static PersistenceActionTarget StartupTarget() => new(
        PersistenceActionKind.StartupFile, ResponsePrivilege.CurrentUser, "synthetic startup",
        null, null, null, Path.Combine(Path.GetTempPath(), "winsight-synthetic-unopened.exe"), "synthetic token");

    private sealed class RecordingMutator : IPersistenceMutator
    {
        public int Calls { get; private set; }
        public PersistenceActionTarget? Target { get; private set; }
        public byte[]? Payload { get; private set; }
        public PersistenceSnapshot? Capture(PersistenceActionTarget target) => throw new InvalidOperationException("Unexpected capture.");
        public PersistenceMutationOutcome RemoveIfUnchanged(PersistenceActionTarget target, PersistenceSnapshot expected) =>
            throw new InvalidOperationException("Unexpected removal.");

        public PersistenceMutationOutcome RestoreIfFree(PersistenceActionTarget target, byte[] payload)
        {
            Calls++;
            Target = target;
            Payload = payload;
            return PersistenceMutationOutcome.Succeeded;
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "winsight-envelope-" + Guid.NewGuid().ToString("N"));
        public Guid BlockId { get; } = Guid.NewGuid();
        public Quarantine Quarantine { get; }
        public QuarantineItem Item { get; }
        public ActionJournal Journal { get; }

        public Fixture(byte[] payload, QuarantineItemKind kind = QuarantineItemKind.RegistryValue)
        {
            Quarantine = new Quarantine(Path.Combine(_root, "quarantine"));
            Journal = new ActionJournal(Path.Combine(_root, "journal.jsonl"));
            Item = Quarantine.Store(kind, "synthetic origin", "synthetic entry", BlockId, payload, DateTimeOffset.UtcNow)!;
            Assert.NotNull(Item);
            Assert.True(Journal.TryAppend(new ActionJournalEntry(BlockId, ResponseActionKind.QuarantinePersistence,
                ResponseOutcome.Succeeded, "synthetic entry", DateTimeOffset.UtcNow, Reversible: true)));
        }

        public void AssertCompleted(ResponseResult result, ResponseOutcome expected)
        {
            var rows = File.ReadAllLines(Path.Combine(_root, "journal.jsonl"))
                .Select(line => JsonSerializer.Deserialize<ActionJournalEntry>(line)!)
                .Where(entry => entry.ActionId == result.ActionId).ToArray();
            Assert.Equal(2, rows.Length);
            Assert.Equal(ActionJournalPhase.Prepared, rows[0].Phase);
            Assert.Equal(ResponseOutcome.AuditPrepared, rows[0].Outcome);
            Assert.Equal(ActionJournalPhase.Completed, rows[1].Phase);
            Assert.Equal(expected, rows[1].Outcome);
            var block = Assert.Single(Journal.Read(), entry => entry.ActionId == BlockId);
            Assert.Equal(expected == ResponseOutcome.Succeeded ? result.ActionId : (Guid?)null, block.UndoneByActionId);
        }

        public void Dispose() => Directory.Delete(_root, recursive: true);
    }
}
