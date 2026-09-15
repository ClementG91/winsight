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
        public bool OriginFree { get; set; }
        public bool Removed { get; private set; }
        public byte[]? Restored { get; private set; }

        public PersistenceSnapshot? Capture(PersistenceActionTarget target) =>
            Token is null ? null : new PersistenceSnapshot(Payload, Token);

        public bool Remove(PersistenceActionTarget target)
        {
            if (!RemoveSucceeds)
            {
                return false;
            }
            Removed = true;
            return true;
        }

        public bool OriginIsFree(PersistenceActionTarget target) => OriginFree;

        public bool Restore(PersistenceActionTarget target, byte[] payload)
        {
            Restored = payload;
            return true;
        }
    }
}
