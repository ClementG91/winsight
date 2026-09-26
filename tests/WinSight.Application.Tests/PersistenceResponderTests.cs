using Microsoft.Win32;

using WinSight.Application;
using WinSight.Core;
using WinSight.Persistence;
using WinSight.Response;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class PersistenceResponderTests
{
    private static AutostartEntry RunEntry(string name = "Updater", string command = @"C:\u.exe", string location =
        @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run [Registry64]") =>
        new(AutostartVector.RunKey, name, location, command, command, command,
            ImageResolutionStatus.Present, SignatureVerdict.Unknown);

    [Fact]
    public void ResolvesAnHkcuRunValueAsAUserAction()
    {
        var target = PersistenceActionResolver.Resolve(RunEntry())!;
        Assert.Equal(PersistenceActionKind.RegistryValue, target.Kind);
        Assert.Equal(ResponsePrivilege.CurrentUser, target.Privilege);
        Assert.Equal(RegistryHive.CurrentUser, target.Hive);
        Assert.Equal("Updater", target.ValueName);
        Assert.Equal(@"Software\Microsoft\Windows\CurrentVersion\Run", target.SubKey);
    }

    [Fact]
    public void ResolvesAnHklmRunValueAsAServiceTierAction()
    {
        var target = PersistenceActionResolver.Resolve(RunEntry(location:
            @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run [Registry64]"))!;
        Assert.Equal(ResponsePrivilege.Service, target.Privilege);
    }

    [Fact]
    public void RefusesAnUnsupportedVector()
    {
        var service = new AutostartEntry(AutostartVector.Service, "svc", @"HKLM\SYSTEM\...\Services\svc",
            @"C:\svc.exe", @"C:\svc.exe", @"C:\svc.exe", ImageResolutionStatus.Present, SignatureVerdict.Unknown);
        Assert.Null(PersistenceActionResolver.Resolve(service));
    }

    [Fact]
    public void BlockQuarantinesAndRemovesWhenTheEntryStillMatches()
    {
        var target = PersistenceActionResolver.Resolve(RunEntry())!;
        var mutator = new FakeMutator { Token = @"C:\u.exe", Payload = [1, 2, 3] };
        var responder = Responder(mutator, out var quarantine);

        var result = responder.Block(target);

        Assert.Equal(ResponseOutcome.Succeeded, result.Outcome);
        Assert.True(result.Reversible);
        Assert.True(mutator.Removed);
        // The quarantined copy is keyed to the block action, the one handle restore takes.
        Assert.Equal(result.ActionId, Assert.Single(quarantine.List()).ActionId);
    }

    [Fact]
    public void BlockRefusesWhenTheValueChangedSinceTheAlert()
    {
        var target = PersistenceActionResolver.Resolve(RunEntry(command: @"C:\u.exe"))!;
        var mutator = new FakeMutator { Token = @"C:\different.exe", Payload = [1] };
        var responder = Responder(mutator, out var quarantine);

        var result = responder.Block(target);

        Assert.Equal(ResponseOutcome.TargetChanged, result.Outcome);
        Assert.False(result.Reversible);
        Assert.False(mutator.Removed);
        Assert.Empty(quarantine.List());
    }

    [Fact]
    public void BlockRefusesWhenTheEntryIsAlreadyGone()
    {
        var target = PersistenceActionResolver.Resolve(RunEntry())!;
        var mutator = new FakeMutator { Token = null };
        var responder = Responder(mutator, out _);

        Assert.Equal(ResponseOutcome.TargetNotFound, responder.Block(target).Outcome);
    }

    [Fact]
    public void AFailedRemovalDiscardsTheQuarantineCopy()
    {
        var target = PersistenceActionResolver.Resolve(RunEntry())!;
        var mutator = new FakeMutator { Token = @"C:\u.exe", Payload = [1], RemoveSucceeds = false };
        var responder = Responder(mutator, out var quarantine);

        Assert.Equal(ResponseOutcome.Failed, responder.Block(target).Outcome);
        Assert.Empty(quarantine.List()); // no orphan copy that would restore a duplicate
    }

    [Fact]
    public void AReplacementBetweenCaptureAndRemovalIsRefusedAndNeverDeleted()
    {
        var target = PersistenceActionResolver.Resolve(RunEntry())!;
        var mutator = new FakeMutator
        {
            Token = @"C:\u.exe",
            Payload = [1],
            ForcedRemovalOutcome = PersistenceMutationOutcome.TargetChanged,
        };
        var responder = Responder(mutator, out var quarantine);

        var result = responder.Block(target);

        Assert.Equal(ResponseOutcome.TargetChanged, result.Outcome);
        Assert.False(mutator.Removed);
        Assert.Empty(quarantine.List());
    }

    [Fact]
    public void MissingAtomicRegistrySupportIsReportedAndLeavesNoQuarantineCopy()
    {
        var target = PersistenceActionResolver.Resolve(RunEntry())!;
        var mutator = new FakeMutator
        {
            Token = @"C:\u.exe",
            Payload = [1],
            ForcedRemovalOutcome = PersistenceMutationOutcome.AtomicityUnavailable,
        };
        var responder = Responder(mutator, out var quarantine);

        var result = responder.Block(target);

        Assert.Equal(ResponseOutcome.NotSupported, result.Outcome);
        Assert.False(result.Reversible);
        Assert.False(mutator.Removed);
        Assert.Empty(quarantine.List());
    }

    /// <summary>
    /// An entry re-created the moment it was removed is not reported as blocked.
    /// </summary>
    /// <remarks>
    /// A program that watches its own Run value and writes it back defeats a plain removal. Reporting
    /// Succeeded would tell the operator the item is gone while it is live again. The quarantine copy
    /// is kept - it is exactly what was removed - and a restore refuses while the origin is occupied,
    /// so keeping it cannot create a duplicate.
    /// </remarks>
    [Fact]
    public void AnEntryReassertedAfterRemovalIsPartiallyAppliedAndExplained()
    {
        var target = PersistenceActionResolver.Resolve(RunEntry())!;
        var mutator = new FakeMutator
        {
            Token = @"C:\u.exe",
            Payload = [1],
            ForcedRemovalOutcome = PersistenceMutationOutcome.Reasserted,
        };
        var responder = Responder(mutator, out var quarantine);

        var result = responder.Block(target);

        Assert.Equal(ResponseOutcome.PartiallyApplied, result.Outcome);
        Assert.Equal(PersistenceResponder.ReassertedDetail, result.Detail);
        Assert.True(result.Reversible);
        Assert.Single(quarantine.List());
    }

    [Fact]
    public void RestorePutsTheEntryBackWhenTheOriginIsFree()
    {
        var target = PersistenceActionResolver.Resolve(RunEntry())!;
        var mutator = new FakeMutator { Token = @"C:\u.exe", Payload = [9, 8, 7] };
        var responder = Responder(mutator, out _);
        var block = responder.Block(target);

        mutator.OriginFree = true;
        var restore = responder.Restore(block.ActionId);

        Assert.Equal(ResponseOutcome.Succeeded, restore.Outcome);
        Assert.Equal([9, 8, 7], mutator.Restored);
    }

    [Fact]
    public void RestoreRefusesWhenSomethingElseOccupiesTheOrigin()
    {
        var target = PersistenceActionResolver.Resolve(RunEntry())!;
        var mutator = new FakeMutator { Token = @"C:\u.exe", Payload = [1] };
        var responder = Responder(mutator, out _);
        var block = responder.Block(target);

        mutator.OriginFree = false;
        Assert.Equal(ResponseOutcome.TargetChanged, responder.Restore(block.ActionId).Outcome);
    }

    [Fact]
    public void AnUnavailableAuditIntentPreventsPersistenceMutation()
    {
        var target = PersistenceActionResolver.Resolve(RunEntry())!;
        var mutator = new FakeMutator { Token = @"C:\u.exe", Payload = [1] };
        var journal = new SequencedJournal(false);
        var responder = new PersistenceResponder(mutator, journal: journal);

        var result = responder.Block(target);

        Assert.Equal(ResponseOutcome.Failed, result.Outcome);
        Assert.Contains("not attempted", result.Detail, StringComparison.Ordinal);
        Assert.Equal(0, mutator.CaptureCalls);
        Assert.False(mutator.Removed);
    }

    [Fact]
    public void ABlockWhoseCompletionCannotBeJournalledIsPartiallyApplied()
    {
        var target = PersistenceActionResolver.Resolve(RunEntry())!;
        var mutator = new FakeMutator { Token = @"C:\u.exe", Payload = [1] };
        var journal = new SequencedJournal(true, false);
        var responder = new PersistenceResponder(mutator, journal: journal);

        var result = responder.Block(target);

        Assert.Equal(ResponseOutcome.PartiallyApplied, result.Outcome);
        Assert.Contains("could not be journalled", result.Detail, StringComparison.Ordinal);
        Assert.True(mutator.Removed);
        Assert.Equal(ActionJournalPhase.Prepared, Assert.Single(journal.Written).Phase);
    }

    private static PersistenceResponder Responder(IPersistenceMutator mutator, out Quarantine quarantine)
    {
        var root = Path.Combine(Path.GetTempPath(), $"winsight-presp-{Guid.NewGuid():N}");
        quarantine = new Quarantine(root);
        var journal = Path.Combine(root, "journal.jsonl");
        return new PersistenceResponder(mutator, quarantine, new ActionJournal(journal),
            () => new DateTimeOffset(2026, 9, 14, 12, 0, 0, TimeSpan.Zero));
    }

    private sealed class FakeMutator : IPersistenceMutator
    {
        public string? Token { get; set; }
        public byte[] Payload { get; set; } = [];
        public bool RemoveSucceeds { get; set; } = true;
        public PersistenceMutationOutcome? ForcedRemovalOutcome { get; set; }
        public bool OriginFree { get; set; }
        public bool Removed { get; private set; }
        public int CaptureCalls { get; private set; }
        public byte[]? Restored { get; private set; }

        public PersistenceSnapshot? Capture(PersistenceActionTarget target)
        {
            CaptureCalls++;
            return Token is null ? null : new PersistenceSnapshot(Payload, Token);
        }

        public PersistenceMutationOutcome RemoveIfUnchanged(
            PersistenceActionTarget target, PersistenceSnapshot expected)
        {
            if (ForcedRemovalOutcome is { } forced)
            {
                return forced;
            }
            if (!RemoveSucceeds)
            {
                return PersistenceMutationOutcome.Failed;
            }
            Removed = true;
            return PersistenceMutationOutcome.Succeeded;
        }

        public PersistenceMutationOutcome RestoreIfFree(PersistenceActionTarget target, byte[] payload)
        {
            if (!OriginFree)
            {
                return PersistenceMutationOutcome.TargetChanged;
            }
            Restored = payload;
            return PersistenceMutationOutcome.Succeeded;
        }
    }

    private sealed class SequencedJournal(params bool[] outcomes) : IActionJournal
    {
        private readonly Queue<bool> _outcomes = new(outcomes);
        public List<ActionJournalEntry> Written { get; } = [];

        public bool TryAppend(ActionJournalEntry entry)
        {
            var succeeds = _outcomes.Count == 0 || _outcomes.Dequeue();
            if (succeeds)
            {
                Written.Add(entry);
            }
            return succeeds;
        }

        public void MarkUndone(Guid actionId, Guid undoActionId)
        {
        }

        public IReadOnlyList<ActionJournalEntry> Read(int max = 200) => Written;
    }
}
