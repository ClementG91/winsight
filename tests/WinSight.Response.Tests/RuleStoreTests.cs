using System.Security.AccessControl;
using System.Security.Principal;

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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ASharingLockNeverReportsRemovalAndPreservesAllRules(bool anotherRule)
    {
        var store = Store();
        var rule = store.Add(Rule())!;
        var other = anotherRule ? store.Add(Rule(item: "run:other")) : null;
        using (var locked = new FileStream(Path.Combine(_directory, "rules.json"), FileMode.Open,
                   FileAccess.Read, FileShare.ReadWrite))
        {
            Assert.False(store.Remove(rule.Id));
        }
        var reloaded = Store().ActiveRules(RuleScopeKind.Persistence);
        Assert.Contains(reloaded, r => r.Id == rule.Id);
        Assert.Equal(anotherRule ? 2 : 1, reloaded.Count);
        Assert.True(store.Remove(rule.Id));
        Assert.DoesNotContain(Store().ActiveRules(RuleScopeKind.Persistence), r => r.Id == rule.Id);
        if (other is not null)
        {
            Assert.Equal(other.Id, Assert.Single(Store().ActiveRules(RuleScopeKind.Persistence)).Id);
        }
    }

    [Fact]
    public void AccessDeniedCannotReportLastRuleRemoval()
    {
        var store = Store();
        var rule = store.Add(Rule())!;
        var directory = new DirectoryInfo(_directory);
        var original = directory.GetAccessControl();
        var denied = directory.GetAccessControl();
        denied.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!,
            FileSystemRights.CreateFiles, AccessControlType.Deny));
        try
        {
            directory.SetAccessControl(denied);
            Assert.False(store.Remove(rule.Id));
        }
        finally
        {
            directory.SetAccessControl(original);
        }
        Assert.Equal(rule.Id, Assert.Single(Store().ActiveRules(RuleScopeKind.Persistence)).Id);
    }

    [Fact]
    public void AddingARuleNeverOverwritesCorruptEvidence()
    {
        var path = Path.Combine(_directory, "rules.json");
        File.WriteAllText(path, "{ not json");
        Assert.Null(Store().Add(Rule()));
        Assert.Equal("{ not json", File.ReadAllText(path));
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

    [Fact]
    public void LockTimeoutFailsClosedWithoutWritingARule()
    {
        var path = Path.Combine(_directory, "contended-rules.json");
        using var lockHeld = new ManualResetEventSlim();
        using var releaseLock = new ManualResetEventSlim();
        Exception? holderFailure = null;
        var holder = new Thread(() =>
        {
            try
            {
                using var mutex = new Mutex(false, RuleStore.LockNameFor(path));
                if (!mutex.WaitOne(TimeSpan.FromSeconds(5)))
                {
                    throw new TimeoutException("Test holder could not acquire the rule-store mutex.");
                }
                lockHeld.Set();
                releaseLock.Wait(CancellationToken.None);
                mutex.ReleaseMutex();
            }
            catch (Exception ex)
            {
                holderFailure = ex;
                lockHeld.Set();
            }
        });
        holder.Start();
        try
        {
            Assert.True(lockHeld.Wait(TimeSpan.FromSeconds(5)));
            Assert.Null(holderFailure);
            var store = new RuleStore(path, () => _now, TimeSpan.FromMilliseconds(100));

            Assert.Null(store.Add(Rule(item: "run:must-not-be-written")));
            Assert.False(File.Exists(path));
        }
        finally
        {
            releaseLock.Set();
            Assert.True(holder.Join(TimeSpan.FromSeconds(5)));
        }
        Assert.Null(holderFailure);
    }
}
