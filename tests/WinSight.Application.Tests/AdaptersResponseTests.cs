using WinSight.Application;
using WinSight.Core;
using WinSight.Persistence;
using WinSight.Reporting;
using WinSight.Response;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// The command-line response surface: every refusal path, and the undo verbs against a fixture state.
/// Nothing here changes a real process: the process-action tests only prove what is refused.
/// </summary>
public sealed class AdaptersResponseTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-cli-response-").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private GuardianAlertPresenter Presenter() =>
        new(new FakeMutator(),
            new Quarantine(Path.Combine(_root, "quarantine")),
            new RuleStore(Path.Combine(_root, "rules.json")),
            new ActionJournal(Path.Combine(_root, "journal.jsonl")));

    private static AutostartEntry RunEntry() =>
        new(AutostartVector.RunKey, "Updater", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run [Registry64]",
            @"C:\u.exe", @"C:\u.exe", @"C:\u.exe", ImageResolutionStatus.Present, SignatureVerdict.Unsigned);

    [Theory]
    [InlineData(ResponseOutcome.Succeeded, CliContract.Clean)]
    [InlineData(ResponseOutcome.Failed, CliContract.UnexpectedFailure)]
    [InlineData(ResponseOutcome.TargetProtected, CliContract.Notable)]
    [InlineData(ResponseOutcome.TargetChanged, CliContract.Notable)]
    [InlineData(ResponseOutcome.TargetNotFound, CliContract.Notable)]
    [InlineData(ResponseOutcome.NotSupported, CliContract.Notable)]
    public void EveryOutcomeMapsToOneExitCode(ResponseOutcome outcome, int expected) =>
        Assert.Equal(expected, Adapters.ExitCodeFor(outcome));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-pid")]
    [InlineData("-5")]
    public void AMalformedPidIsAUsageErrorAndNothingIsTouched(string? pid) =>
        Assert.Equal(CliContract.UsageError,
            Adapters.RespondToProcess(ResponseActionKind.TerminateProcess, pid, confirmed: true));

    [Fact]
    public void AProcessActionWithoutConfirmIsRefusedBeforeTheProcessIsEvenRead() =>
        Assert.Equal(CliContract.UsageError, Adapters.RespondToProcess(
            ResponseActionKind.TerminateProcess, Environment.ProcessId.ToString(), confirmed: false));

    [Fact]
    public void AProtectedProcessIsRefusedEvenWhenConfirmed() =>
        // pid 4 is the System process.
        Assert.Equal(CliContract.Notable,
            Adapters.RespondToProcess(ResponseActionKind.TerminateProcess, "4", confirmed: true));

    [Fact]
    public void HoldersRefusesANonLocalArgument()
    {
        var report = Adapters.DescribeHolders(@"\\server\share\decoy.docx");

        Assert.Equal("holderTarget", Assert.Single(report.Items).Fields["kind"]);
        Assert.Equal(1, report.NotableCount);
    }

    [Fact]
    public void HoldersNeverOffersItsOwnProcessForResponse()
    {
        var path = Path.Combine(_root, "held.dat");
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite);

        var report = Adapters.DescribeHolders(path);

        Assert.Empty(report.Items);
        Assert.Contains("protected", report.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, report.NotableCount); // holding a file is inventory, not a finding
    }

    [Theory]
    [InlineData(null, true)]
    [InlineData("not-a-guid", true)]
    [InlineData("11111111-1111-1111-1111-111111111111", false)]
    public void UndoVerbsRefuseAMalformedIdOrAMissingConfirm(string? id, bool confirmed)
    {
        var presenter = Presenter();

        Assert.Equal(CliContract.UsageError, Adapters.RestoreBlocked(presenter, id, confirmed));
        Assert.Equal(CliContract.UsageError, Adapters.RevokeRule(presenter, id, confirmed));
    }

    [Fact]
    public void RestorePutsBackABlockedItemByItsBlockId()
    {
        var presenter = Presenter();
        var block = presenter.Block(RunEntry());

        Assert.Equal(CliContract.Clean, Adapters.RestoreBlocked(presenter, block.ActionId.ToString(), confirmed: true));
        Assert.Equal(CliContract.Notable, Adapters.RestoreBlocked(presenter, block.ActionId.ToString(), confirmed: true));
    }

    [Fact]
    public void RevokeRemovesAnAllowAndAnUnknownRuleIsNotable()
    {
        var presenter = Presenter();
        var rule = presenter.Allow(RunEntry())!;

        Assert.Equal(CliContract.Clean, Adapters.RevokeRule(presenter, rule.Id.ToString(), confirmed: true));
        Assert.Equal(CliContract.Notable, Adapters.RevokeRule(presenter, rule.Id.ToString(), confirmed: true));
    }

    [Fact]
    public void RulesListsEachAllowWithTheIdThatRevokesIt()
    {
        var presenter = Presenter();
        Assert.Empty(Adapters.Rules(presenter).Items);

        var rule = presenter.Allow(RunEntry())!;
        var report = Adapters.Rules(presenter);

        var item = Assert.Single(report.Items);
        Assert.Equal(rule.Id.ToString(), item.Fields["ruleId"]);
        Assert.Equal(Severity.Info, item.Severity);
        Assert.Contains("winsight revoke", report.Summary, StringComparison.Ordinal);
    }

    private sealed class FakeMutator : IPersistenceMutator
    {
        public PersistenceSnapshot? Capture(PersistenceActionTarget target) => new([1], @"C:\u.exe");
        public PersistenceMutationOutcome RemoveIfUnchanged(
            PersistenceActionTarget target, PersistenceSnapshot expected) => PersistenceMutationOutcome.Succeeded;
        public PersistenceMutationOutcome RestoreIfFree(
            PersistenceActionTarget target, byte[] payload) => PersistenceMutationOutcome.Succeeded;
    }
}
