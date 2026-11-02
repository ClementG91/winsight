using System.Text.Json;
using System.Text.Json.Nodes;

using WinSight.Core;
using WinSight.Persistence;
using WinSight.Response;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class ProducerDiagnosticsTests : IDisposable
{
    private static readonly ActionJournalPhase[] ExpectedPhases = [ActionJournalPhase.Prepared, ActionJournalPhase.Completed];
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-producer-diagnostics-").FullName;
    private string RulesPath => Path.Combine(_root, "rules.json");
    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Theory]
    [InlineData(ActionJournalWriteStatus.Appended)]
    [InlineData(ActionJournalWriteStatus.EvidenceRecoveryBlocked)]
    public void PersistenceDiagnosticsRetainBothReassertionAndCompletionFailure(ActionJournalWriteStatus completion)
    {
        var journal = new ObservedJournal(ActionJournalWriteStatus.Rotated, completion);
        var mutator = new Mutator(PersistenceMutationOutcome.Reasserted);
        var quarantine = new Quarantine(Path.Combine(_root, "quarantine"));
        var responder = new PersistenceResponder(mutator, quarantine, journal);

        var result = responder.Block(PersistenceActionResolver.Resolve(Entry())!);

        Assert.Equal(ResponseOutcome.PartiallyApplied, result.Outcome);
        Assert.True(result.Reversible);
        Assert.Equal(1, mutator.Removals);
        Assert.Single(quarantine.List());
        var diagnostics = Assert.IsType<ResponseDiagnostics>(result.Diagnostics);
        Assert.True(diagnostics.PersistenceReasserted);
        Assert.False(diagnostics.ProcessRollbackIncomplete);
        Assert.Same(journal.Results[0], diagnostics.AuditIntent);
        Assert.Same(journal.Results[1], diagnostics.AuditCompletion);
        Assert.Null(diagnostics.RuleMutation);
        Assert.Null(diagnostics.AllowRollback);
        Assert.Equal(completion == ActionJournalWriteStatus.Appended
            ? PersistenceResponder.ReassertedDetail
            : "the action may have changed the target, but its completion could not be journalled; " + journal.Results[1].Detail,
            result.Detail);
        Assert.Equal(ExpectedPhases, journal.Entries.Select(x => x.Phase));
    }

    [Theory]
    [InlineData(PersistenceMutationOutcome.Succeeded, ResponseOutcome.PartiallyApplied, true)]
    [InlineData(PersistenceMutationOutcome.TargetChanged, ResponseOutcome.TargetChanged, false)]
    [InlineData(PersistenceMutationOutcome.Failed, ResponseOutcome.Failed, false)]
    public void OrdinaryBlockOutcomesNeverInventReassertion(PersistenceMutationOutcome removal, ResponseOutcome expected, bool reversible)
    {
        var journal = new ObservedJournal(ActionJournalWriteStatus.Appended, ActionJournalWriteStatus.Unavailable);
        var mutator = new Mutator(removal);
        var responder = new PersistenceResponder(mutator, new Quarantine(Path.Combine(_root, "quarantine")), journal);
        var result = responder.Block(PersistenceActionResolver.Resolve(Entry())!);
        Assert.Equal(expected, result.Outcome);
        Assert.Equal(reversible, result.Reversible);
        var diagnostics = Assert.IsType<ResponseDiagnostics>(result.Diagnostics);
        Assert.False(diagnostics.PersistenceReasserted);
        Assert.False(diagnostics.ProcessRollbackIncomplete);
        Assert.Same(journal.Results[0], diagnostics.AuditIntent);
        Assert.Same(journal.Results[1], diagnostics.AuditCompletion);
        Assert.Contains(removal == PersistenceMutationOutcome.Succeeded
            ? "the action may have changed the target"
            : "the refusal/failure completion could not be journalled", result.Detail, StringComparison.Ordinal);
        Assert.Equal(1, mutator.Removals);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PersistenceIntentRefusalHasNoMutationOrInventedCompletion(bool restore)
    {
        var journal = new ObservedJournal(ActionJournalWriteStatus.LockTimeout);
        var mutator = new Mutator(PersistenceMutationOutcome.Succeeded);
        var responder = new PersistenceResponder(mutator, new Quarantine(Path.Combine(_root, "quarantine")), journal);
        var result = restore ? responder.Restore(Guid.NewGuid()) : responder.Block(PersistenceActionResolver.Resolve(Entry())!);
        Assert.Equal(ResponseOutcome.Failed, result.Outcome);
        Assert.False(result.Reversible);
        Assert.Equal(0, mutator.Captures + mutator.Removals + mutator.Restores);
        var diagnostics = Assert.IsType<ResponseDiagnostics>(result.Diagnostics);
        Assert.Same(Assert.Single(journal.Results), diagnostics.AuditIntent);
        Assert.Null(diagnostics.AuditCompletion);
        Assert.False(diagnostics.PersistenceReasserted);
        Assert.Empty(journal.UndoCalls);
    }

    [Theory]
    [InlineData(ActionJournalWriteStatus.Updated)]
    [InlineData(ActionJournalWriteStatus.Unavailable)]
    public void RestoreCarriesActualCompletionAndDoesNotInventAnnotationEvidence(ActionJournalWriteStatus completion)
    {
        var journal = new ObservedJournal(ActionJournalWriteStatus.Appended, ActionJournalWriteStatus.Appended,
            ActionJournalWriteStatus.Rotated, completion);
        var mutator = new Mutator(PersistenceMutationOutcome.Succeeded);
        var responder = new PersistenceResponder(mutator, new Quarantine(Path.Combine(_root, "quarantine")), journal);
        var block = responder.Block(PersistenceActionResolver.Resolve(Entry())!);
        var restored = responder.Restore(block.ActionId);
        var diagnostics = Assert.IsType<ResponseDiagnostics>(restored.Diagnostics);
        Assert.Same(journal.Results[2], diagnostics.AuditIntent);
        Assert.Same(journal.Results[3], diagnostics.AuditCompletion);
        Assert.False(diagnostics.PersistenceReasserted);
        Assert.Null(diagnostics.RuleMutation);
        Assert.Null(diagnostics.AllowRollback);
        Assert.Equal(completion == ActionJournalWriteStatus.Updated ? ResponseOutcome.Succeeded : ResponseOutcome.PartiallyApplied, restored.Outcome);
        Assert.False(restored.Reversible);
        Assert.Equal(1, mutator.Restores);
        Assert.Equal(completion == ActionJournalWriteStatus.Updated ? 1 : 0, journal.UndoCalls.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AllowAndRevokeIntentRefusalHaveNoRuleMutation(bool revoke)
    {
        var journal = new ObservedJournal(ActionJournalWriteStatus.UnsafeLockPath);
        var presenter = new GuardianAlertPresenter(rules: new RuleStore(RulesPath), journal: journal);
        ResponseResult result;
        if (revoke) { Assert.Equal(ResponseOutcome.Failed, presenter.Revoke(Guid.NewGuid(), out result)); }
        else { Assert.Null(presenter.Allow(Entry(), out result)); }
        var diagnostics = Assert.IsType<ResponseDiagnostics>(result.Diagnostics);
        Assert.Same(Assert.Single(journal.Results), diagnostics.AuditIntent);
        Assert.Null(diagnostics.RuleMutation);
        Assert.Null(diagnostics.AuditCompletion);
        Assert.Null(diagnostics.AllowRollback);
        Assert.False(File.Exists(RulesPath));
        Assert.Empty(journal.UndoCalls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SuccessfulAllowCarriesIgnoredAndRetainedCountsEvenWhenDetailIsNull(bool invalidNeighbor)
    {
        var future = JsonSerializer.SerializeToNode(new ResponseRule(Guid.NewGuid(), RuleScopeKind.Persistence,
            RuleDecision.Allow, RuleDuration.Permanent, DateTimeOffset.UtcNow, Item: "future"))!;
        future["Decision"] = 999;
        var entries = new JsonArray(future);
        if (invalidNeighbor) { entries.Add((JsonNode?)null); }
        File.WriteAllText(RulesPath, new JsonObject { ["Version"] = 1, ["Rules"] = entries }.ToJsonString());
        var journal = new ObservedJournal(ActionJournalWriteStatus.Appended, ActionJournalWriteStatus.Rotated);
        var presenter = new GuardianAlertPresenter(rules: new RuleStore(RulesPath), journal: journal);
        var stored = presenter.Allow(Entry(), out var result);
        Assert.NotNull(stored);
        Assert.Equal(ResponseOutcome.Succeeded, result.Outcome);
        Assert.True(result.Reversible);
        var diagnostics = Assert.IsType<ResponseDiagnostics>(result.Diagnostics);
        Assert.Same(journal.Results[0], diagnostics.AuditIntent);
        Assert.Same(journal.Results[1], diagnostics.AuditCompletion);
        var mutation = Assert.IsType<RuleStoreResult>(diagnostics.RuleMutation);
        Assert.Equal(RuleStoreStatus.Written, mutation.Status);
        Assert.Equal(invalidNeighbor ? 1 : 0, mutation.IgnoredEntries);
        Assert.Equal(1, mutation.RetainedUnsupportedEntries);
        Assert.Null(diagnostics.AllowRollback);
        Assert.Equal(invalidNeighbor ? mutation.Detail : null, result.Detail);
        Assert.Equal(stored.Id, Assert.Single(presenter.AllowRules()).Id);
        using var document = JsonDocument.Parse(File.ReadAllBytes(RulesPath));
        Assert.Equal(2, document.RootElement.GetProperty("Rules").GetArrayLength());
    }

    [Theory]
    [InlineData(ActionJournalWriteStatus.Appended)]
    [InlineData(ActionJournalWriteStatus.RetentionLimit)]
    public void RevokeKeepsMutationAndCompletionSeparate(ActionJournalWriteStatus completion)
    {
        var rules = new RuleStore(RulesPath);
        var stored = rules.Add(new ResponseRule(Guid.NewGuid(), RuleScopeKind.Persistence,
            RuleDecision.Allow, RuleDuration.Permanent, DateTimeOffset.UtcNow, Item: "existing"))!;
        var journal = new ObservedJournal(ActionJournalWriteStatus.Rotated, completion);
        var presenter = new GuardianAlertPresenter(rules: rules, journal: journal);
        Assert.Equal(completion == ActionJournalWriteStatus.Appended ? ResponseOutcome.Succeeded : ResponseOutcome.PartiallyApplied,
            presenter.Revoke(stored.Id, out var result));
        var diagnostics = Assert.IsType<ResponseDiagnostics>(result.Diagnostics);
        Assert.Same(journal.Results[0], diagnostics.AuditIntent);
        Assert.Same(journal.Results[1], diagnostics.AuditCompletion);
        Assert.Equal(RuleStoreStatus.Written, Assert.IsType<RuleStoreResult>(diagnostics.RuleMutation).Status);
        Assert.Null(diagnostics.AllowRollback);
        Assert.Empty(presenter.AllowRules());
        Assert.Equal(completion == ActionJournalWriteStatus.Appended ? 1 : 0, journal.UndoCalls.Count);
    }

    [Fact]
    public void AllowRollbackKeepsInitialAndRollbackCountersDistinct()
    {
        var future = JsonSerializer.SerializeToNode(new ResponseRule(Guid.NewGuid(), RuleScopeKind.Persistence,
            RuleDecision.Allow, RuleDuration.Permanent, DateTimeOffset.UtcNow, Item: "future"))!;
        future["Decision"] = 999;
        File.WriteAllText(RulesPath, new JsonObject
        {
            ["Version"] = 1,
            ["Rules"] = new JsonArray(future, null, null),
        }.ToJsonString());
        var journal = new ObservedJournal(ActionJournalWriteStatus.Appended, ActionJournalWriteStatus.Unavailable)
        {
            BeforeCompletion = () =>
            {
                var original = File.ReadAllText(RulesPath);
                using var before = JsonDocument.Parse(original);
                var unchangedRules = before.RootElement.GetProperty("Rules").EnumerateArray()
                    .Select(rule => rule.GetRawText()).ToArray();
                var changed = original.Insert(original.LastIndexOf(']'), ",null");
                File.WriteAllText(RulesPath, changed);
                using var after = JsonDocument.Parse(File.ReadAllBytes(RulesPath));
                var actualRules = after.RootElement.GetProperty("Rules").EnumerateArray().ToArray();
                Assert.Equal(unchangedRules, actualRules.Take(unchangedRules.Length).Select(rule => rule.GetRawText()));
                Assert.Equal(unchangedRules.Length + 1, actualRules.Length);
                Assert.Equal(JsonValueKind.Null, actualRules[^1].ValueKind);
            },
        };
        var presenter = new GuardianAlertPresenter(rules: new RuleStore(RulesPath), journal: journal);
        Assert.Null(presenter.Allow(Entry(), out var result));
        Assert.Equal(ResponseOutcome.Failed, result.Outcome);
        var diagnostics = Assert.IsType<ResponseDiagnostics>(result.Diagnostics);
        var mutation = Assert.IsType<RuleStoreResult>(diagnostics.RuleMutation);
        Assert.Equal(RuleStoreStatus.Written, mutation.Status);
        Assert.Equal(2, mutation.IgnoredEntries);
        Assert.Equal(1, mutation.RetainedUnsupportedEntries);
        var rollback = Assert.IsType<AllowRollbackDiagnostic>(diagnostics.AllowRollback);
        Assert.Equal(AllowRollbackState.ConfirmedAbsent, rollback.State);
        Assert.Equal(ResponseOutcome.Succeeded, rollback.Outcome);
        Assert.Equal(RuleStoreStatus.Written, rollback.Storage.Status);
        Assert.Equal(1, rollback.Storage.IgnoredEntries);
        Assert.Equal(1, rollback.Storage.RetainedUnsupportedEntries);
        Assert.Empty(presenter.AllowRules());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FailedRuleMutationStillCarriesBothStorageAndAuditFailuresWithoutRollback(bool revoke)
    {
        File.WriteAllText(RulesPath, "invalid JSON");
        var before = File.ReadAllBytes(RulesPath);
        var journal = new ObservedJournal(ActionJournalWriteStatus.Appended, ActionJournalWriteStatus.RotationFailed);
        var presenter = new GuardianAlertPresenter(rules: new RuleStore(RulesPath), journal: journal);
        ResponseResult result;
        if (revoke) { Assert.Equal(ResponseOutcome.Failed, presenter.Revoke(Guid.NewGuid(), out result)); }
        else { Assert.Null(presenter.Allow(Entry(), out result)); }
        Assert.Equal(ResponseOutcome.Failed, result.Outcome);
        var diagnostics = Assert.IsType<ResponseDiagnostics>(result.Diagnostics);
        Assert.Equal(RuleStoreStatus.InvalidJson, Assert.IsType<RuleStoreResult>(diagnostics.RuleMutation).Status);
        Assert.Same(journal.Results[1], diagnostics.AuditCompletion);
        Assert.Null(diagnostics.AllowRollback);
        Assert.Equal(before, File.ReadAllBytes(RulesPath));
    }

    private static AutostartEntry Entry() => new(AutostartVector.RunKey, "Updater",
        @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run [Registry64]",
        @"D:\u.exe", @"D:\u.exe", @"D:\u.exe", ImageResolutionStatus.Present, SignatureVerdict.Unsigned);

    private sealed class Mutator(PersistenceMutationOutcome removal) : IPersistenceMutator
    {
        public int Captures { get; private set; }
        public int Removals { get; private set; }
        public int Restores { get; private set; }
        public PersistenceSnapshot Capture(PersistenceActionTarget target) { Captures++; return new([1, 2, 3], target.RevalidationToken); }
        public PersistenceMutationOutcome RemoveIfUnchanged(PersistenceActionTarget target, PersistenceSnapshot expected) { Removals++; return removal; }
        public PersistenceMutationOutcome RestoreIfFree(PersistenceActionTarget target, byte[] payload) { Restores++; return PersistenceMutationOutcome.Succeeded; }
    }

    private sealed class ObservedJournal(params ActionJournalWriteStatus[] statuses) : IActionJournal
    {
        public Action? BeforeCompletion { get; init; }
        public List<ActionJournalEntry> Entries { get; } = [];
        public List<ActionJournalWriteResult> Results { get; } = [];
        public List<(Guid Action, Guid Undo)> UndoCalls { get; } = [];
        public ActionJournalWriteResult TryAppendWithStatus(ActionJournalEntry entry)
        {
            if (entry.Phase == ActionJournalPhase.Completed) { BeforeCompletion?.Invoke(); }
            var result = new ActionJournalWriteResult(statuses[Entries.Count]);
            Entries.Add(entry); Results.Add(result); return result;
        }
        public bool TryAppend(ActionJournalEntry entry) => TryAppendWithStatus(entry).Durable;
        public void MarkUndone(Guid actionId, Guid undoActionId) => UndoCalls.Add((actionId, undoActionId));
        public IReadOnlyList<ActionJournalEntry> Read(int max = 200) => Entries;
    }
}
