using WinSight.Core;
using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// A source that is routinely partly unreadable (another user's hive, a protected task folder, an
/// ACL'd service key) used to confirm no removal anywhere, so a remove-and-reinstall in the readable
/// part was never re-alerted. Absence is now confirmed outside the attributed unreadable scopes.
/// </summary>
public sealed class GuardianScopedAbsenceTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 14, 12, 0, 0, TimeSpan.Zero);
    private const string Source = "Other user hives";

    private static AutostartEntry Hive(string sid, string name) =>
        Entries.Unsigned(AutostartVector.RunKey, name, $@"C:\{name}.exe") with
        {
            Location = $@"HKU\{sid}\Software\Microsoft\Windows\CurrentVersion\Run [Registry64]",
            Source = Source,
        };

    private static PersistenceScanResult Partial(IReadOnlyCollection<string>? scopes, params AutostartEntry[] entries) =>
        new(entries, new PersistenceCoverage(1, [Source]), new HashSet<string>())
        {
            PartialSources = scopes is null ? null : new Dictionary<string, IReadOnlyCollection<string>> { [Source] = scopes },
        };

    [Fact]
    public void RemovalAndReinstallInTheReadablePartAlertsAgainWhileTheUnreadablePartIsRetained()
    {
        var readable = Hive("S-1-5-21-1-1001", "Updater");
        var hidden = Hive("S-1-5-21-1-1002", "Hidden");
        var core = new PersistenceMonitorCore();
        core.SeedBaseline([readable, hidden]);
        string[] scopes = [@"HKU\S-1-5-21-1-1002"];

        Assert.Empty(core.Reconcile(Partial(scopes), T0));        // both absent from this read
        Assert.Contains(PersistenceIdentity.FromEntry(hidden), core.CurrentBaseline);
        Assert.DoesNotContain(PersistenceIdentity.FromEntry(readable), core.CurrentBaseline);

        var reinstalled = Assert.Single(core.Reconcile(Partial(scopes, readable), T0.AddMinutes(1)));
        Assert.Equal("Updater", reinstalled.Entry.Name);
        Assert.Empty(core.Reconcile(Partial(scopes, readable, hidden), T0.AddMinutes(2)));
    }

    [Theory]
    [InlineData(@"HKU\S-1-5-21-1-100")]          // prefix of another SID must not cover it
    [InlineData(@"HKU\S-1-5-21-1-1001\Software\Other")]
    public void AScopeCoversOnlyItsOwnKeyPath(string scope)
    {
        var entry = Hive("S-1-5-21-1-1001", "Updater");
        var core = new PersistenceMonitorCore();
        core.SeedBaseline([entry]);

        core.Reconcile(Partial([scope]), T0);

        Assert.Empty(core.CurrentBaseline);
    }

    [Fact]
    public void AnUnattributedGapKeepsTheWholeSourceConservative()
    {
        var entry = Hive("S-1-5-21-1-1001", "Updater");
        var core = new PersistenceMonitorCore();
        core.SeedBaseline([entry]);

        core.Reconcile(Partial(scopes: null), T0);

        Assert.Single(core.CurrentBaseline);
    }

    [Fact]
    public void ScopesAreCaseInsensitiveAndApplyToPersistedStartupReconciliation()
    {
        var hidden = Hive("S-1-5-21-1-1002", "Hidden");
        var gone = Hive("S-1-5-21-1-1001", "Gone");
        var core = new PersistenceMonitorCore();

        core.ReconcileFromPersistedBaseline(
            new HashSet<PersistenceIdentity> { PersistenceIdentity.FromEntry(hidden), PersistenceIdentity.FromEntry(gone) },
            Partial([@"hku\s-1-5-21-1-1002"]),
            T0);

        Assert.Equal(PersistenceIdentity.FromEntry(hidden), Assert.Single(core.CurrentBaseline));
    }

    [Fact]
    public void TheScannerOnlyAcceptsScopesFromSourcesThatCanConfirmAbsence()
    {
        var scan = new PersistenceScanner(
            [new ScopedSurface("scoped", reliable: true, [@"HKU\S-1"]),
             new ScopedSurface("unattributed", reliable: true, null),
             new ScopedSurface("unreliable", reliable: false, [@"HKU\S-2"])],
            new NoSignatures()).ScanWithCoverage();

        Assert.Equal(["scoped"], scan.PartialSources!.Keys);
        Assert.Empty(scan.CompleteSources!);
    }

    [Fact]
    public void DeniedTaskFoldersBecomeScopesAndAnUnnamedFolderMakesTheGapUnattributed()
    {
        var gaps = new List<string>();
        var root = new Folder(@"\", [new Folder(@"\Microsoft\Windows\Protected", deny: true), new Folder(@"\Visible", [])]);

        Assert.False(ComScheduledTaskSource.Collect(root, [], depth: 0, gaps));
        Assert.Equal([@"\Microsoft\Windows\Protected"], gaps);

        var unnamed = new List<string>();
        Assert.False(ComScheduledTaskSource.Collect(new Folder(@"\", [new Folder(null, deny: true)]), [], 0, unnamed));
        Assert.Contains(ComScheduledTaskSource.UnattributedFolder, unnamed);
    }

    [Fact]
    public void TheTaskEnumeratorTranslatesFolderGapsIntoLocationScopes()
    {
        var enumerator = new ScheduledTaskEnumerator(new ScriptedTasks([@"\Microsoft\Windows\Protected"]));
        _ = enumerator.Enumerate().ToList();

        var scope = Assert.Single(enumerator.UnreadableScopes!);
        Assert.EndsWith(@"Tasks\Microsoft\Windows\Protected", scope, StringComparison.OrdinalIgnoreCase);

        var unattributed = new ScheduledTaskEnumerator(new ScriptedTasks(null));
        _ = unattributed.Enumerate().ToList();
        Assert.Null(unattributed.UnreadableScopes);
    }

    public sealed class Folder(string? path, IReadOnlyList<object>? folders = null, bool deny = false)
    {
        public string? Path => path ?? throw new UnauthorizedAccessException("no path");
        public IEnumerable<object> GetTasks(int flags) =>
            deny ? throw new UnauthorizedAccessException("folder denied") : [];
        public IEnumerable<object> GetFolders(int flags) => folders ?? [];
    }

    private sealed class ScriptedTasks(IReadOnlyCollection<string>? folders) : IScheduledTaskSource
    {
        public bool Unreadable => true;
        public IReadOnlyCollection<string>? UnreadableFolders => folders;
        public IEnumerable<ScheduledTaskDefinition> Enumerate() => [];
    }

    private sealed class ScopedSurface(string name, bool reliable, IReadOnlyCollection<string>? scopes) : IAutostartEnumerator
    {
        public string Surface => name;
        public bool CanConfirmAbsence => reliable;
        public int UnreadableLocations => 1;
        public IReadOnlyCollection<string>? UnreadableScopes => scopes;
        public IEnumerable<RawAutostart> Enumerate() => [];
    }

    private sealed class NoSignatures : ISignatureVerifier
    {
        public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default) => SignatureVerdict.Missing;
        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default) =>
            new Dictionary<string, SignatureVerdict>();
    }
}
