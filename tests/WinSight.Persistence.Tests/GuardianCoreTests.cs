using WinSight.Core;
using WinSight.Persistence;

using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// Helpers for building resolved autostart entries in tests, so each test states only the
/// fields it cares about.
/// </summary>
internal static class Entries
{
    public static AutostartEntry Signed(
        AutostartVector vector, string name, string target, string signer = "Contoso") =>
        new(vector, name, $"loc:{name}", target, target, target,
            ImageResolutionStatus.Present,
            new SignatureVerdict(SignatureState.SignedTrusted, signer));

    public static AutostartEntry Unsigned(
        AutostartVector vector, string name, string target) =>
        new(vector, name, $"loc:{name}", target, target, target,
            ImageResolutionStatus.Present, SignatureVerdict.Unsigned);

    public static AutostartEntry Missing(
        AutostartVector vector, string name, string target) =>
        new(vector, name, $"loc:{name}", target, null, target,
            ImageResolutionStatus.FileMissing, SignatureVerdict.Missing);
}

public sealed class PersistenceIdentityTests
{
    [Fact]
    public void FromEntry_IsCaseInsensitiveAndSeparatorInsensitive()
    {
        var a = Entries.Signed(AutostartVector.RunKey, "Updater", @"C:\Apps\Up.exe");
        var b = Entries.Signed(AutostartVector.RunKey, "updater", @"c:/apps/up.exe");

        Assert.Equal(PersistenceIdentity.FromEntry(a), PersistenceIdentity.FromEntry(b));
    }

    [Fact]
    public void FromEntry_DifferentVector_IsDifferentIdentity()
    {
        var run = Entries.Signed(AutostartVector.RunKey, "X", @"C:\a.exe");
        var svc = Entries.Signed(AutostartVector.Service, "X", @"C:\a.exe");

        Assert.NotEqual(PersistenceIdentity.FromEntry(run), PersistenceIdentity.FromEntry(svc));
    }

    [Fact]
    public void FromEntry_PrefersExpectedPath_SoAMissingFileStillHasStableIdentity()
    {
        // Same expected target, one currently missing and one resolved: same identity, because a
        // file appearing on disk must not read as a brand-new persistence entry.
        var missing = Entries.Missing(AutostartVector.Service, "Svc", @"C:\Windows\svc.exe");
        var present = Entries.Signed(AutostartVector.Service, "Svc", @"C:\Windows\svc.exe");

        Assert.Equal(PersistenceIdentity.FromEntry(missing), PersistenceIdentity.FromEntry(present));
    }

    [Fact]
    public void Canonicalize_BlankOrQuoted_IsStable()
    {
        Assert.Equal(string.Empty, PersistenceIdentity.Canonicalize("   "));
        Assert.Equal(@"c:\a b\x.exe", PersistenceIdentity.Canonicalize("  \"C:\\a b\\x.exe\" "));
    }
}

public sealed class PersistenceDiffEngineTests
{
    private static HashSet<PersistenceIdentity> Baseline(params AutostartEntry[] entries) =>
        entries.Select(PersistenceIdentity.FromEntry).ToHashSet();

    [Fact]
    public void Diff_NewIdentity_IsAdded()
    {
        var baseline = Baseline(Entries.Signed(AutostartVector.RunKey, "Old", @"C:\old.exe"));
        var fresh = new[]
        {
            Entries.Signed(AutostartVector.RunKey, "Old", @"C:\old.exe"),
            Entries.Unsigned(AutostartVector.RunKey, "New", @"C:\new.exe"),
        };

        var result = PersistenceDiffEngine.Diff(baseline, fresh);

        Assert.Single(result.Added);
        Assert.Equal("New", result.Added[0].Name);
        Assert.Empty(result.Removed);
    }

    [Fact]
    public void Diff_DisappearedBaselineEntry_IsRemoved()
    {
        var gone = Entries.Signed(AutostartVector.RunKey, "Gone", @"C:\gone.exe");
        var baseline = Baseline(gone, Entries.Signed(AutostartVector.RunKey, "Stay", @"C:\stay.exe"));
        var fresh = new[] { Entries.Signed(AutostartVector.RunKey, "Stay", @"C:\stay.exe") };

        var result = PersistenceDiffEngine.Diff(baseline, fresh);

        Assert.Empty(result.Added);
        Assert.Equal(PersistenceIdentity.FromEntry(gone), Assert.Single(result.Removed));
    }

    [Fact]
    public void Diff_DuplicateIdentityInFreshScan_IsAddedOnce()
    {
        var baseline = Baseline();
        var dup = Entries.Signed(AutostartVector.RunKey, "Dup", @"C:\dup.exe");
        var result = PersistenceDiffEngine.Diff(baseline, new[] { dup, dup });

        Assert.Single(result.Added);
    }

    [Fact]
    public void Diff_NoChange_IsEmpty()
    {
        var e = Entries.Signed(AutostartVector.RunKey, "A", @"C:\a.exe");
        var result = PersistenceDiffEngine.Diff(Baseline(e), new[] { e });

        Assert.Empty(result.Added);
        Assert.Empty(result.Removed);
    }
}

public sealed class PersistenceChangeLogTests
{
    private static readonly DateTimeOffset T0 = new(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Observe_FirstTime_ReturnsEvent_RepeatReturnsNullAndCountsObservation()
    {
        var log = new PersistenceChangeLog();
        var e = Entries.Unsigned(AutostartVector.RunKey, "X", @"C:\x.exe");

        var first = log.Observe(e, T0);
        var second = log.Observe(e, T0.AddSeconds(5));

        Assert.NotNull(first);
        Assert.Null(second);
        var snap = Assert.Single(log.Snapshot());
        Assert.Equal(2, snap.Observations);
        Assert.Equal(T0.AddSeconds(5), snap.LastSeenUtc);
        Assert.Equal(T0, snap.FirstSeenUtc);
    }

    [Fact]
    public void Observe_IsBounded_AndCountsDroppedWithoutEvicting()
    {
        var log = new PersistenceChangeLog();
        for (var i = 0; i < PersistenceChangeLog.MaxChanges; i++)
        {
            Assert.NotNull(log.Observe(Entries.Signed(AutostartVector.RunKey, $"E{i}", $@"C:\e{i}.exe"), T0));
        }

        // The interesting one arrives after the log is full: it is refused, not swapped in.
        var overflow = log.Observe(Entries.Unsigned(AutostartVector.RunKey, "Evil", @"C:\evil.exe"), T0);

        Assert.Null(overflow);
        Assert.Equal(1, log.DroppedChanges);
        Assert.Equal(PersistenceChangeLog.MaxChanges, log.Snapshot().Count);
        Assert.DoesNotContain(log.Snapshot(), e => e.Entry.Name == "Evil");
    }

    [Fact]
    public void Snapshot_IsMostRecentFirst()
    {
        var log = new PersistenceChangeLog();
        log.Observe(Entries.Signed(AutostartVector.RunKey, "Older", @"C:\o.exe"), T0);
        log.Observe(Entries.Signed(AutostartVector.RunKey, "Newer", @"C:\n.exe"), T0.AddMinutes(1));

        Assert.Equal("Newer", log.Snapshot()[0].Entry.Name);
    }

    [Fact]
    public void Acknowledge_RemovesEntry()
    {
        var log = new PersistenceChangeLog();
        var e = Entries.Unsigned(AutostartVector.RunKey, "X", @"C:\x.exe");
        log.Observe(e, T0);

        Assert.True(log.Acknowledge(PersistenceIdentity.FromEntry(e)));
        Assert.Empty(log.Snapshot());
    }

    [Fact]
    public void IsNotable_TracksSuspicion_SignedIsQuiet_UnsignedAndMissingAreLoud()
    {
        var log = new PersistenceChangeLog();
        var signed = log.Observe(Entries.Signed(AutostartVector.RunKey, "Ok", @"C:\ok.exe"), T0);
        var unsigned = log.Observe(Entries.Unsigned(AutostartVector.RunKey, "Bad", @"C:\bad.exe"), T0);
        var missing = log.Observe(Entries.Missing(AutostartVector.Service, "Ghost", @"C:\ghost.exe"), T0);

        Assert.False(signed!.IsNotable);
        Assert.True(unsigned!.IsNotable);
        Assert.True(missing!.IsNotable);
    }
}

public sealed class PersistenceMonitorCoreTests
{
    private static readonly DateTimeOffset T0 = new(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void SeedBaseline_ThenReconcileSameScan_SurfacesNothing()
    {
        var core = new PersistenceMonitorCore();
        var scan = new[] { Entries.Unsigned(AutostartVector.RunKey, "X", @"C:\x.exe") };

        core.SeedBaseline(scan);
        var detected = core.Reconcile(scan, T0);

        Assert.Empty(detected);
        Assert.Empty(core.Log.Snapshot());
    }

    [Fact]
    public void Reconcile_WithoutSeeding_SeedsSilentlyOnFirstScan()
    {
        var core = new PersistenceMonitorCore();
        var scan = new[] { Entries.Unsigned(AutostartVector.RunKey, "X", @"C:\x.exe") };

        var detected = core.Reconcile(scan, T0);

        Assert.False(detected.Any());
        Assert.True(core.IsSeeded);
        // The same entry on a later scan is now known, so still silent.
        Assert.Empty(core.Reconcile(scan, T0.AddMinutes(1)));
    }

    [Fact]
    public void Reconcile_NewEntryAfterBaseline_IsDetectedOnce()
    {
        var core = new PersistenceMonitorCore();
        core.SeedBaseline(new[] { Entries.Signed(AutostartVector.RunKey, "Old", @"C:\old.exe") });

        var withNew = new[]
        {
            Entries.Signed(AutostartVector.RunKey, "Old", @"C:\old.exe"),
            Entries.Unsigned(AutostartVector.RunKey, "New", @"C:\new.exe"),
        };

        var first = core.Reconcile(withNew, T0);
        var second = core.Reconcile(withNew, T0.AddMinutes(1));

        Assert.Equal("New", Assert.Single(first).Entry.Name);
        Assert.Empty(second); // added to baseline, so not re-reported
        Assert.Single(core.Log.Snapshot());
    }

    [Fact]
    public void SeedBaseline_IsIdempotent()
    {
        var core = new PersistenceMonitorCore();
        core.SeedBaseline(new[] { Entries.Signed(AutostartVector.RunKey, "A", @"C:\a.exe") });
        // A second seeding attempt with a different set must NOT change the baseline.
        core.SeedBaseline(new[] { Entries.Unsigned(AutostartVector.RunKey, "B", @"C:\b.exe") });

        // "B" is therefore unknown and must be detected as new on reconcile.
        var detected = core.Reconcile(
            new[] { Entries.Unsigned(AutostartVector.RunKey, "B", @"C:\b.exe") }, T0);

        Assert.Equal("B", Assert.Single(detected).Entry.Name);
    }

    [Fact]
    public void Reconcile_FullLog_StillAdvancesBaseline_NoRunawayDrops()
    {
        var log = new PersistenceChangeLog();
        for (var i = 0; i < PersistenceChangeLog.MaxChanges; i++)
        {
            log.Observe(Entries.Signed(AutostartVector.RunKey, $"Seed{i}", $@"C:\s{i}.exe"), T0);
        }
        var core = new PersistenceMonitorCore(log);
        core.SeedBaseline(Array.Empty<AutostartEntry>());

        var scan = new[] { Entries.Unsigned(AutostartVector.RunKey, "Over", @"C:\over.exe") };
        core.Reconcile(scan, T0);
        core.Reconcile(scan, T0.AddMinutes(1));

        // Refused by the full log both times would runaway-count; baseline advancement caps it at 1.
        Assert.Equal(1, log.DroppedChanges);
    }
}
