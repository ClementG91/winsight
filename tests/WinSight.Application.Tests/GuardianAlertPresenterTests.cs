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

        public bool Remove(PersistenceActionTarget target)
        {
            Removed = true;
            return true;
        }

        public bool OriginIsFree(PersistenceActionTarget target) => true;

        public bool Restore(PersistenceActionTarget target, byte[] payload)
        {
            Restored = payload;
            return true;
        }
    }
}
