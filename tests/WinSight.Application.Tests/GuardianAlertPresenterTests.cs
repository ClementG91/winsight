using WinSight.Application;
using WinSight.Core;
using WinSight.Persistence;
using WinSight.Response;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class GuardianAlertPresenterTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 9, 15, 12, 0, 0, TimeSpan.Zero);

    private readonly string _root = Directory.CreateTempSubdirectory("winsight-alert-").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private string JournalPath => Path.Combine(_root, "journal.jsonl");

    private GuardianAlertPresenter Presenter(FakeMutator mutator) =>
        new(mutator,
            new Quarantine(Path.Combine(_root, "quarantine")),
            new RuleStore(Path.Combine(_root, "rules.json"), () => Now),
            new ActionJournal(JournalPath),
            () => Now);

    private static AutostartEntry RunEntry(
        string name = "Updater",
        string location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run [Registry64]") =>
        new(AutostartVector.RunKey, name, location, @"C:\u.exe", @"C:\u.exe", @"C:\u.exe",
            ImageResolutionStatus.Present, SignatureVerdict.Unsigned);

    private static AutostartEntry ServiceEntry() =>
        new(AutostartVector.Service, "svc", @"HKLM\SYSTEM\...\Services\svc",
            @"C:\svc.exe", @"C:\svc.exe", @"C:\svc.exe", ImageResolutionStatus.Present, SignatureVerdict.Unsigned);

    [Fact]
    public void AnHkcuRunValueCanBeBlocked()
    {
        var options = GuardianAlertPresenter.Describe(RunEntry());

        Assert.Equal(AlertActionAvailability.Supported, options.Availability);
        Assert.True(options.CanBlock);
    }

    [Fact]
    public void AMachineWideItemIsNotActionableUntilTheServiceTierShips()
    {
        var options = GuardianAlertPresenter.Describe(
            RunEntry(location: @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run [Registry64]"));

        Assert.Equal(AlertActionAvailability.RequiresService, options.Availability);
        Assert.False(options.CanBlock);
    }

    [Fact]
    public void AnUnsupportedVectorIsReportedRatherThanGuessed()
    {
        var options = GuardianAlertPresenter.Describe(ServiceEntry());

        Assert.Equal(AlertActionAvailability.UnsupportedVector, options.Availability);
        Assert.False(options.CanBlock);
    }

    [Fact]
    public void BlockingAnItemThatNeedsTheServiceIsRefusedWithoutTouchingTheMachine()
    {
        var mutator = new FakeMutator();

        var result = Presenter(mutator).Block(
            RunEntry(location: @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run [Registry64]"));

        Assert.Equal(ResponseOutcome.NotAuthorized, result.Outcome);
        Assert.False(mutator.Removed);
    }

    [Fact]
    public void BlockThenRestoreByTheBlockActionIdPutsTheEntryBackAndMarksTheBlockUndone()
    {
        var mutator = new FakeMutator { Payload = [9, 9] };
        var presenter = Presenter(mutator);

        var block = presenter.Block(RunEntry());
        Assert.Equal(ResponseOutcome.Succeeded, block.Outcome);
        Assert.True(block.Reversible);
        Assert.True(mutator.Removed);

        var restore = presenter.Restore(block.ActionId);

        Assert.Equal(ResponseOutcome.Succeeded, restore.Outcome);
        Assert.Equal([9, 9], mutator.Restored);
        var blockEntry = Assert.Single(new ActionJournal(JournalPath).Read(),
            e => e.ActionId == block.ActionId);
        Assert.Equal(restore.ActionId, blockEntry.UndoneByActionId);
    }

    [Fact]
    public void RestoringAnUnknownIdIsNotFound() =>
        Assert.Equal(ResponseOutcome.TargetNotFound, Presenter(new FakeMutator()).Restore(Guid.NewGuid()).Outcome);

    [Fact]
    public void AllowStoresAJournalledRuleThatThenSuppressesTheSameEntry()
    {
        var presenter = Presenter(new FakeMutator());
        var entry = RunEntry();
        Assert.Null(presenter.SuppressingRule(entry));

        var rule = presenter.Allow(entry);

        Assert.NotNull(rule);
        // The rule that silences the entry is named, so the journal can record which one did.
        Assert.Equal(rule!.Id, presenter.SuppressingRule(entry)!.Id);
        Assert.Equal(rule.Id, Assert.Single(presenter.AllowRules()).Id);
        var journalled = Assert.Single(new ActionJournal(JournalPath).Read());
        Assert.Equal(ResponseActionKind.AddRule, journalled.Kind);
        Assert.Equal(rule.Id, journalled.ActionId); // the rule id is the handle `winsight revoke` takes
    }

    [Fact]
    public void RevokeRemovesTheAllowSoTheItemAlertsAgainAndMarksTheAllowUndone()
    {
        var presenter = Presenter(new FakeMutator());
        var entry = RunEntry();
        var rule = presenter.Allow(entry)!;

        Assert.Equal(ResponseOutcome.Succeeded, presenter.Revoke(rule.Id));

        Assert.Null(presenter.SuppressingRule(entry));
        Assert.Empty(presenter.AllowRules());
        var journal = new ActionJournal(JournalPath).Read();
        Assert.Contains(journal, e => e.Kind == ResponseActionKind.RemoveRule);
        Assert.NotNull(Assert.Single(journal, e => e.ActionId == rule.Id).UndoneByActionId);
    }

    [Fact]
    public void RevokingAnUnknownRuleIsNotFound() =>
        Assert.Equal(ResponseOutcome.TargetNotFound, Presenter(new FakeMutator()).Revoke(Guid.NewGuid()));

    [Fact]
    public void LockedRevokeIsFailedInTheResponseAndJournalAndLeavesTheAllowActive()
    {
        var presenter = Presenter(new FakeMutator());
        var rule = presenter.Allow(RunEntry())!;
        using (var locked = new FileStream(Path.Combine(_root, "rules.json"), FileMode.Open,
                   FileAccess.Read, FileShare.ReadWrite))
        {
            Assert.Equal(ResponseOutcome.Failed, presenter.Revoke(rule.Id));
        }
        Assert.Equal(rule.Id, Assert.Single(new RuleStore(Path.Combine(_root, "rules.json"))
            .ActiveRules(RuleScopeKind.Persistence)).Id);
        var history = new ActionJournal(JournalPath).Read();
        Assert.Equal(ResponseOutcome.Failed,
            Assert.Single(history, e => e.Kind == ResponseActionKind.RemoveRule).Outcome);
        Assert.Null(Assert.Single(history, e => e.ActionId == rule.Id).UndoneByActionId);
    }

    [Theory]
    [InlineData("{ not json")]
    [InlineData("{\"Version\":99,\"Rules\":[]}")]
    public void UnreadableRuleStoreIsFailedRatherThanTargetNotFound(string content)
    {
        File.WriteAllText(Path.Combine(_root, "rules.json"), content);
        Assert.Equal(ResponseOutcome.Failed, Presenter(new FakeMutator()).Revoke(Guid.NewGuid()));
        Assert.Equal(ResponseOutcome.Failed, Assert.Single(new ActionJournal(JournalPath).Read()).Outcome);
        Assert.Equal(content, File.ReadAllText(Path.Combine(_root, "rules.json")));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AllowCompletionFailureReturnsTheActualPersistedState(bool blockRollback)
    {
        var path = Path.Combine(_root, "rollback-rules.json");
        using var journal = new CompletionFailingJournal(path, blockRollback);
        var presenter = new GuardianAlertPresenter(new FakeMutator(), rules: new RuleStore(path),
            journal: journal, clock: () => Now);
        var returned = presenter.Allow(RunEntry());
        journal.ReleaseLock();
        var reloaded = new RuleStore(path).ActiveRules(RuleScopeKind.Persistence);
        Assert.Equal(blockRollback, returned is not null);
        Assert.Equal(blockRollback ? 1 : 0, reloaded.Count);
        if (returned is not null)
        {
            Assert.Equal(returned.Id, Assert.Single(reloaded).Id);
        }
        var intent = Assert.Single(journal.Read());
        Assert.Equal(ActionJournalPhase.Prepared, intent.Phase);
        Assert.Equal(ResponseOutcome.AuditPrepared, intent.Outcome);
    }

    [Fact]
    public void RevokeIsNotAttemptedWhenItsAuditIntentCannotBeWritten()
    {
        var store = new RuleStore(Path.Combine(_root, "rules-intent.json"), () => Now);
        var rule = new ResponseRule(Guid.NewGuid(), RuleScopeKind.Persistence, RuleDecision.Allow,
            RuleDuration.Permanent, Now, Item: "item");
        Assert.NotNull(store.Add(rule));
        var presenter = new GuardianAlertPresenter(
            new FakeMutator(), rules: store, journal: new SequencedJournal(false), clock: () => Now);

        Assert.Equal(ResponseOutcome.Failed, presenter.Revoke(rule.Id));
        Assert.Equal(rule.Id, Assert.Single(store.ActiveRules(RuleScopeKind.Persistence)).Id);
    }

    [Fact]
    public void RevokeCompletionFailureIsPartiallyApplied()
    {
        var store = new RuleStore(Path.Combine(_root, "rules-completion.json"), () => Now);
        var rule = new ResponseRule(Guid.NewGuid(), RuleScopeKind.Persistence, RuleDecision.Allow,
            RuleDuration.Permanent, Now, Item: "item");
        Assert.NotNull(store.Add(rule));
        var presenter = new GuardianAlertPresenter(
            new FakeMutator(), rules: store, journal: new SequencedJournal(true, false), clock: () => Now);

        Assert.Equal(ResponseOutcome.PartiallyApplied, presenter.Revoke(rule.Id));
        Assert.Empty(store.ActiveRules(RuleScopeKind.Persistence));
    }

    [Fact]
    public void AnAllowThatCannotBeStoredReturnsNullAndIsJournalledAsFailed()
    {
        var presenter = new GuardianAlertPresenter(
            new FakeMutator(), rules: new RuleStore("C:\\invalid\0rules.json"), journal: new ActionJournal(JournalPath));

        Assert.Null(presenter.Allow(RunEntry()));
        Assert.Equal(ResponseOutcome.Failed, Assert.Single(new ActionJournal(JournalPath).Read()).Outcome);
    }

    [Fact]
    public void AnAllowRuleDoesNotSuppressADifferentItem()
    {
        var presenter = Presenter(new FakeMutator());
        presenter.Allow(RunEntry(name: "Updater"));

        Assert.Null(presenter.SuppressingRule(RunEntry(name: "SomethingElse")));
    }

    [Fact]
    public void AllowOnAnUnsupportedVectorStillSilencesThatImage()
    {
        var presenter = Presenter(new FakeMutator());

        Assert.NotNull(presenter.Allow(ServiceEntry()));
        Assert.NotNull(presenter.SuppressingRule(ServiceEntry()));
    }

    private sealed class FakeMutator : IPersistenceMutator
    {
        public byte[] Payload { get; init; } = [1, 2, 3];
        public bool Removed { get; private set; }
        public byte[]? Restored { get; private set; }

        public PersistenceSnapshot? Capture(PersistenceActionTarget target) => new(Payload, @"C:\u.exe");

        public PersistenceMutationOutcome RemoveIfUnchanged(
            PersistenceActionTarget target, PersistenceSnapshot expected)
        {
            Removed = true;
            return PersistenceMutationOutcome.Succeeded;
        }

        public PersistenceMutationOutcome RestoreIfFree(PersistenceActionTarget target, byte[] payload)
        {
            Restored = payload;
            return PersistenceMutationOutcome.Succeeded;
        }
    }

    private sealed class CompletionFailingJournal(string path, bool blockRollback) : IActionJournal, IDisposable
    {
        private readonly List<ActionJournalEntry> _entries = [];
        private FileStream? _locked;

        public bool TryAppend(ActionJournalEntry entry)
        {
            if (entry.Phase == ActionJournalPhase.Prepared)
            {
                _entries.Add(entry);
                return true;
            }
            if (blockRollback)
            {
                _locked = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            }
            return false;
        }

        public void MarkUndone(Guid actionId, Guid undoActionId) => throw new InvalidOperationException();
        public IReadOnlyList<ActionJournalEntry> Read(int max = 200) => _entries;
        public void ReleaseLock() => _locked?.Dispose();
        public void Dispose() => ReleaseLock();
    }

    private sealed class SequencedJournal(params bool[] outcomes) : IActionJournal
    {
        private readonly Queue<bool> _outcomes = new(outcomes);

        public bool TryAppend(ActionJournalEntry entry) =>
            _outcomes.Count == 0 || _outcomes.Dequeue();

        public void MarkUndone(Guid actionId, Guid undoActionId)
        {
        }

        public IReadOnlyList<ActionJournalEntry> Read(int max = 200) => [];
    }
}
