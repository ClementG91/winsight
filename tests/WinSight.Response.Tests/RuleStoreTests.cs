using Xunit;

namespace WinSight.Response.Tests;

public sealed class RuleStoreTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("winsight-rules-").FullName;
    private DateTimeOffset _now = new(2026, 9, 14, 12, 0, 0, TimeSpan.Zero);

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private RuleStore Store() => new(Path.Combine(_directory, "rules.json"), () => _now);

    private static ResponseRule Rule(
        RuleScopeKind scope = RuleScopeKind.Persistence, RuleDecision decision = RuleDecision.Allow,
        RuleDuration duration = RuleDuration.Permanent, string? item = "run:updater",
        string? publisher = null, DateTimeOffset? expires = null) =>
        new(Guid.NewGuid(), scope, decision, duration, new DateTimeOffset(2026, 9, 14, 11, 0, 0, TimeSpan.Zero),
            expires, item, ImagePath: null, ImageSha256: null, publisher);

    [Fact]
    public void AnUnusableStoreFailsOpenAndNeverThrows()
    {
        // A path the lock cannot be derived from: every call must honour its contract instead of
        // throwing, because monitors consult the store on every detection.
        var store = new RuleStore("C:\\invalid\0rules.json", () => _now);

        Assert.Null(store.Match(RuleScopeKind.Persistence, item: "run:updater")); // no rule => alert
        Assert.Empty(store.ActiveRules(RuleScopeKind.Persistence));
        Assert.Null(store.Add(Rule(item: "run:updater")));
        Assert.False(store.Remove(Guid.NewGuid()));
    }

    [Fact]
    public void AnAddedRuleMatchesAndRoundTrips()
    {
        var store = Store();
        var rule = store.Add(Rule(item: "run:updater"));

        Assert.NotNull(rule);
        var match = store.Match(RuleScopeKind.Persistence, item: "run:updater");
        Assert.Equal(rule!.Id, match!.Id);
        Assert.Null(store.Match(RuleScopeKind.Ransomware, item: "run:updater"));
        Assert.Null(store.Match(RuleScopeKind.Persistence, item: "run:other"));
    }

    [Fact]
    public void ARuleWithNoKeyAndAOnceRuleAreNeverStored()
    {
        var store = Store();
        Assert.Null(store.Add(Rule(item: null)));
        Assert.Null(store.Add(Rule(duration: RuleDuration.Once)));
        Assert.Empty(store.ActiveRules(RuleScopeKind.Persistence));
    }

    [Fact]
    public void APublisherRuleMatchesAnyImageFromThatPublisher()
    {
        var store = Store();
        store.Add(Rule(item: null, publisher: "CN=Contoso"));

        Assert.NotNull(store.Match(RuleScopeKind.Persistence, imagePath: @"C:\a.exe", publisher: "CN=Contoso"));
        Assert.Null(store.Match(RuleScopeKind.Persistence, imagePath: @"C:\a.exe", publisher: "CN=Evil"));
    }

    [Fact]
    public void ATimedRuleExpires()
    {
        var store = Store();
        store.Add(Rule(duration: RuleDuration.Timed, expires: _now.AddMinutes(10)));
        Assert.NotNull(store.Match(RuleScopeKind.Persistence, item: "run:updater"));

        _now = _now.AddMinutes(11);
        Assert.Null(store.Match(RuleScopeKind.Persistence, item: "run:updater"));
        Assert.Empty(store.ActiveRules(RuleScopeKind.Persistence));
    }

    [Theory]
    [InlineData(RuleDuration.Once)]
    [InlineData(RuleDuration.UntilReboot)]      // no boot-time prune here: it would become "forever"
    [InlineData(RuleDuration.UntilProcessExit)] // no process-exit watch here either
    public void DurationsTheStoreCannotHonourAreRefusedRatherThanStoredAsPermanent(RuleDuration duration)
    {
        var store = Store();

        Assert.Null(store.Add(Rule(duration: duration)));
        Assert.Empty(store.ActiveRules(RuleScopeKind.Persistence));
    }

    [Fact]
    public void RemoveDeletesById()
    {
        var store = Store();
        var rule = store.Add(Rule())!;
        Assert.True(store.Remove(rule.Id));
        Assert.False(store.Remove(rule.Id));
        Assert.Empty(store.ActiveRules(RuleScopeKind.Persistence));
    }

    [Fact]
    public void AMalformedFileYieldsNoRules()
    {
        var path = Path.Combine(_directory, "rules.json");
        File.WriteAllText(path, "{ not json");
        Assert.Empty(new RuleStore(path, () => _now).ActiveRules(RuleScopeKind.Persistence));

        File.WriteAllText(path, "{\"Version\":99,\"Rules\":[]}");
        Assert.Empty(new RuleStore(path, () => _now).ActiveRules(RuleScopeKind.Persistence));
    }

    [Fact]
    public async Task ConcurrentAddsAllSurvive()
    {
        var store = Store();
        using var go = new ManualResetEventSlim();
        var tasks = Enumerable.Range(0, 16).Select(i => Task.Run(() =>
        {
            go.Wait();
            store.Add(Rule(item: $"run:item-{i}"));
        })).ToArray();
        go.Set();
        await Task.WhenAll(tasks);

        Assert.Equal(16, store.ActiveRules(RuleScopeKind.Persistence).Count);
    }
}
