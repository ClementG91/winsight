using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;

using WinSight.Core;
using WinSight.Persistence;
using WinSight.Reporting;
using WinSight.Response;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class RuleStoreRecoveryTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-rule-recovery-").FullName;
    private string PathName => Path.Combine(_root, "rules.json");
    private RuleStore Store => new(PathName);
    public void Dispose() => Directory.Delete(_root, recursive: true);
    private static ResponseRule Rule(string item = "run:valid") => new(Guid.NewGuid(), RuleScopeKind.Persistence,
        RuleDecision.Allow, RuleDuration.Permanent, DateTimeOffset.UtcNow, Item: item);
    private GuardianAlertPresenter Presenter(IActionJournal? journal = null) => new(rules: Store,
        journal: journal ?? new ActionJournal(Path.Combine(_root, "actions.jsonl")));
    private static AutostartEntry Entry() => new(AutostartVector.RunKey, "Updater",
        @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run [Registry64]",
        @"D:\u.exe", @"D:\u.exe", @"D:\u.exe", ImageResolutionStatus.Present, SignatureVerdict.Unsigned);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void NullOrKeylessRulesNeverDisableValidRulesOrFutureWrites(bool keyless)
    {
        var valid = Rule();
        WriteRules(valid, keyless ? Rule() with { Item = null } : null);
        Assert.Equal(valid.Id, Store.Match(RuleScopeKind.Persistence, item: valid.Item)?.Id);
        var original = File.ReadAllBytes(PathName);
        var report = Adapters.Rules(Presenter());
        Assert.Equal(1, report.NotableCount);
        var coverage = Assert.Single(report.Items, item => item.Fields["kind"] == "ruleStoreCoverage");
        Assert.Equal("1", coverage.Fields["ignoredEntries"]);
        Assert.Equal(original, File.ReadAllBytes(PathName));
        var newRule = Rule("run:new");
        Assert.NotNull(Store.Add(newRule));
        Assert.Equal(2, Store.ActiveRules(RuleScopeKind.Persistence).Count);
        Assert.Equal(0, Adapters.Rules(Presenter()).NotableCount);
        Assert.Equal(ResponseOutcome.Succeeded, Store.RemoveWithOutcome(valid.Id));
        Assert.Equal(newRule.Id, Assert.Single(Store.ActiveRules(RuleScopeKind.Persistence)).Id);
    }

    [Theory]
    [InlineData("Scope")]
    [InlineData("Decision")]
    [InlineData("Duration")]
    [InlineData("Once")]
    [InlineData("UntilReboot")]
    [InlineData("UntilProcessExit")]
    [InlineData("EmptyId")]
    [InlineData("MissingDecision")]
    [InlineData("MissingScope")]
    [InlineData("MissingDuration")]
    [InlineData("MissingCreatedUtc")]
    [InlineData("MissingId")]
    [InlineData("TimedWithoutExpiry")]
    [InlineData("WrongType")]
    public void AnInvalidEntryCannotInventAnAllowOrDisableItsValidNeighbor(string defect)
    {
        var valid = Rule();
        var invalid = JsonSerializer.SerializeToNode(Rule("run:unsafe"))!;
        switch (defect)
        {
            case "Scope": case "Decision": case "Duration": invalid[defect] = 99; break;
            case "Once": case "UntilReboot": case "UntilProcessExit": invalid["Duration"] = (int)Enum.Parse<RuleDuration>(defect); break;
            case "EmptyId": invalid["Id"] = Guid.Empty; break;
            case "MissingDecision": case "MissingScope": case "MissingDuration": invalid.AsObject().Remove(defect[7..]); break;
            case "MissingCreatedUtc": case "MissingId": invalid.AsObject().Remove(defect[7..]); break;
            case "TimedWithoutExpiry": invalid["Duration"] = (int)RuleDuration.Timed; invalid["ExpiresUtc"] = null; break;
            case "WrongType": invalid["Scope"] = "not-a-number"; break;
        }
        File.WriteAllText(PathName, new JsonObject
        {
            ["Version"] = 1,
            ["Rules"] = new JsonArray(JsonSerializer.SerializeToNode(valid), invalid),
        }.ToJsonString());
        var original = File.ReadAllBytes(PathName);
        Assert.Equal(valid.Id, Assert.Single(Store.ActiveRules(RuleScopeKind.Persistence)).Id);
        Assert.Null(Store.Match(RuleScopeKind.Persistence, item: "run:unsafe"));
        Assert.Equal(1, Adapters.Rules(Presenter()).NotableCount);
        Assert.Equal(original, File.ReadAllBytes(PathName));
        Assert.Equal(ResponseOutcome.Succeeded, Store.RemoveWithOutcome(valid.Id));
        Assert.Empty(Store.ActiveRules(RuleScopeKind.Persistence));
        Assert.Equal(0, Adapters.Rules(Presenter()).NotableCount);
    }

    [Theory]
    [InlineData("InvalidJson", "{ not json")]
    [InlineData("UnsupportedVersion", "{\"Version\":99,\"Rules\":[]}")]
    [InlineData("InvalidFormat", "{\"Version\":1}")]
    [InlineData("InvalidFormat", "{\"Version\":1,\"Rules\":null}")]
    [InlineData("InvalidFormat", "{\"Rules\":[]}")]
    [InlineData("InvalidFormat", "{\"Version\":99,\"Version\":1,\"Rules\":[]}")]
    [InlineData("InvalidFormat", "{\"Version\":1,\"Rules\":null,\"Rules\":[]}")]
    [InlineData("InvalidFormat", "{\"Version\":null,\"Rules\":[]}")]
    [InlineData("InvalidFormat", "{\"Version\":\"1\",\"Rules\":[]}")]
    [InlineData("InvalidFormat", "{\"Version\":1.5,\"Rules\":[]}")]
    [InlineData("InvalidFormat", "[]")]
    public void UnreadableRuleStatesAreVisibleAndNeverOverwritten(string status, string contents)
    {
        File.WriteAllText(PathName, contents);
        var original = File.ReadAllBytes(PathName);
        var presenter = Presenter();
        Assert.Null(presenter.Allow(Entry(), out var allowed));
        Assert.Equal(ResponseOutcome.Failed, allowed.Outcome);
        Assert.False(allowed.Reversible);
        Assert.Contains(status, allowed.Detail, StringComparison.Ordinal);
        Assert.Equal(ResponseOutcome.Failed, presenter.Revoke(Guid.NewGuid(), out var revoked));
        Assert.Contains(status, revoked.Detail, StringComparison.Ordinal);
        var report = Adapters.Rules(presenter);
        Assert.Equal(1, report.NotableCount);
        Assert.Contains("unavailable", report.Summary, StringComparison.OrdinalIgnoreCase);
        using var text = new StringWriter();
        ReportRenderer.RenderText(report, text);
        Assert.Contains(status, text.ToString(), StringComparison.Ordinal);
        Assert.Equal(original, File.ReadAllBytes(PathName));
    }

    [Fact]
    public void OnlyConfirmedAbsenceIsAHealthyEmptyStore()
    {
        Assert.Equal("Missing", ReadStatus(Store));
        Assert.False(File.Exists(PathName));
        Directory.CreateDirectory(PathName);
        Assert.Equal("Unavailable", ReadStatus(Store));
        Assert.Null(Presenter().Allow(Entry(), out var result));
        Assert.Contains("Unavailable", result.Detail, StringComparison.Ordinal);
        Assert.True(Directory.Exists(PathName));
    }

    [Fact]
    public void ADeniedReadNeverMeansMissingAndBecomesUsableAfterAclRecovery()
    {
        var valid = Store.Add(Rule())!;
        var file = new FileInfo(PathName);
        var original = file.GetAccessControl().GetSecurityDescriptorBinaryForm();
        try
        {
            var denied = file.GetAccessControl();
            denied.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!,
                FileSystemRights.ReadData, AccessControlType.Deny));
            file.SetAccessControl(denied);
            Assert.Equal("Unavailable", ReadStatus(Store));
            Assert.Equal(ResponseOutcome.Failed, Presenter().Revoke(valid.Id, out var result));
            Assert.Contains("Unavailable", result.Detail, StringComparison.Ordinal);
        }
        finally
        {
            var restored = new FileSecurity();
            restored.SetSecurityDescriptorBinaryForm(original, AccessControlSections.Access);
            file.SetAccessControl(restored);
        }
        Assert.Equal(valid.Id, Assert.Single(Store.ActiveRules(RuleScopeKind.Persistence)).Id);
        Assert.Equal(ResponseOutcome.Succeeded, Presenter().Revoke(valid.Id));
    }

    [Fact]
    public void AFailedAtomicRemovalIsPreciseAndRetryNeverLosesTheRule()
    {
        var rule = Store.Add(Rule())!;
        var original = File.ReadAllBytes(PathName);
        using (var locked = new FileStream(PathName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            Assert.Equal(ResponseOutcome.Failed, Presenter().Revoke(rule.Id, out var result));
            Assert.Contains("WriteFailed", result.Detail, StringComparison.Ordinal);
            Assert.Equal(original, File.ReadAllBytes(PathName));
        }
        Assert.Equal(rule.Id, Assert.Single(Store.ActiveRules(RuleScopeKind.Persistence)).Id);
        Assert.Equal(ResponseOutcome.Succeeded, Presenter().Revoke(rule.Id));
    }

    [Fact]
    public void RuleBudgetsAreVisibleAndASameIdReplacementWorksAtCapacity()
    {
        var rules = Enumerable.Range(0, 8192).Select(i => Rule($"run:{i}")).ToArray();
        WriteRules(rules);
        Assert.Equal(rules.Length, Store.ActiveRules(RuleScopeKind.Persistence).Count);
        Assert.NotNull(Store.Add(rules[0] with { Item = "run:replacement" }));
        var atCapacity = File.ReadAllBytes(PathName);
        Assert.Null(Presenter().Allow(Entry(), out var full));
        Assert.Contains("RuleLimit", full.Detail, StringComparison.Ordinal);
        Assert.Equal(atCapacity, File.ReadAllBytes(PathName));
        WriteRules(rules.Cast<ResponseRule?>().Append(null).ToArray());
        var overLimit = File.ReadAllBytes(PathName);
        Assert.Null(Presenter().Allow(Entry(), out var over));
        Assert.Contains("RuleLimit", over.Detail, StringComparison.Ordinal);
        Assert.Equal(overLimit, File.ReadAllBytes(PathName));
        File.WriteAllText(PathName, new string(' ', 8 * 1024 * 1024 + 1));
        var oversized = File.ReadAllBytes(PathName);
        Assert.Null(Presenter().Allow(Entry(), out var large));
        Assert.Contains("ByteLimit", large.Detail, StringComparison.Ordinal);
        Assert.Equal(oversized, File.ReadAllBytes(PathName));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AnAllowRolledBackOrAlreadyRevokedIsNeverReportedAsReversible(bool revokedBeforeRollback)
    {
        var journal = new CompletionFailureJournal(() =>
        {
            if (revokedBeforeRollback)
            {
                var id = Assert.Single(Store.ActiveRules(RuleScopeKind.Persistence)).Id;
                Assert.Equal(ResponseOutcome.Succeeded, Presenter().Revoke(id));
            }
        });
        Assert.Null(Presenter(journal).Allow(Entry(), out var result));
        Assert.Equal(ResponseOutcome.Failed, result.Outcome);
        Assert.False(result.Reversible);
        Assert.Empty(Store.ActiveRules(RuleScopeKind.Persistence));
        Assert.Single(journal.Entries);
        Assert.Equal(ActionJournalPhase.Prepared, journal.Entries[0].Phase);
    }

    [Fact]
    public void AnUnreadableRollbackNeverClaimsThatAConcurrentlyRevokedRuleIsActive()
    {
        byte[]? original = null;
        var journal = new CompletionFailureJournal(() =>
        {
            var id = Assert.Single(Store.ActiveRules(RuleScopeKind.Persistence)).Id;
            Assert.Equal(ResponseOutcome.Succeeded, Presenter().Revoke(id));
            var file = new FileInfo(PathName);
            original = file.GetAccessControl().GetSecurityDescriptorBinaryForm();
            var denied = file.GetAccessControl();
            denied.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!,
                FileSystemRights.ReadData, AccessControlType.Deny));
            file.SetAccessControl(denied);
        });
        try
        {
            Assert.Null(Presenter(journal).Allow(Entry(), out var result));
            Assert.Equal(ResponseOutcome.PartiallyApplied, result.Outcome);
            Assert.False(result.Reversible);
            Assert.Contains("Unavailable", result.Detail, StringComparison.Ordinal);
            Assert.Contains("active state is unconfirmed", result.Detail, StringComparison.Ordinal);
            Assert.DoesNotContain("rule remains active", result.Detail, StringComparison.Ordinal);
        }
        finally
        {
            if (original is not null)
            {
                var restored = new FileSecurity();
                restored.SetSecurityDescriptorBinaryForm(original, AccessControlSections.Access);
                new FileInfo(PathName).SetAccessControl(restored);
            }
        }
        Assert.Empty(Store.ActiveRules(RuleScopeKind.Persistence));
    }

    [Fact]
    public void FailedRollbackTruthfullyKeepsTheActiveAllowAndExplainsItsStorageFailure()
    {
        var directory = new DirectoryInfo(_root);
        var original = directory.GetAccessControl().GetSecurityDescriptorBinaryForm();
        var journal = new CompletionFailureJournal(() =>
        {
            var denied = directory.GetAccessControl();
            denied.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!,
                FileSystemRights.CreateFiles, AccessControlType.Deny));
            directory.SetAccessControl(denied);
        });
        try
        {
            var stored = Presenter(journal).Allow(Entry(), out var result);
            Assert.NotNull(stored);
            Assert.Equal(ResponseOutcome.PartiallyApplied, result.Outcome);
            Assert.True(result.Reversible);
            Assert.Equal(stored.Id, Assert.Single(Store.ActiveRules(RuleScopeKind.Persistence)).Id);
            Assert.Contains("WriteFailed", result.Detail, StringComparison.Ordinal);
            Assert.Single(journal.Entries);
        }
        finally
        {
            var restored = new DirectorySecurity();
            restored.SetSecurityDescriptorBinaryForm(original, AccessControlSections.Access);
            directory.SetAccessControl(restored);
        }
        Assert.Equal(ResponseOutcome.Succeeded, Presenter().Revoke(Assert.Single(Store.ActiveRules(RuleScopeKind.Persistence)).Id));
    }

    [Fact]
    public void NewRulesMustHaveKnownSemanticsAndACompleteIdentity()
    {
        var valid = Rule();
        foreach (var invalid in new[]
        {
            valid with { Scope = (RuleScopeKind)99 }, valid with { Decision = (RuleDecision)99 },
            valid with { Duration = (RuleDuration)99 }, valid with { Id = Guid.Empty },
            valid with { Duration = RuleDuration.Timed, ExpiresUtc = null },
        })
        {
            Assert.Null(Store.Add(invalid));
            Assert.False(File.Exists(PathName));
        }
        Assert.NotNull(Store.Add(valid)); // Explicit zero-valued enums are supported.
    }

    [Fact]
    public void RuleWritersUseTheSameMutexAcrossCooperatingWindowsSessions()
    {
        var method = typeof(RuleStore).GetMethod("LockNameFor", BindingFlags.Static | BindingFlags.NonPublic)!;
        Assert.StartsWith(@"Global\", Assert.IsType<string>(method.Invoke(null, [PathName])), StringComparison.Ordinal);
    }

    private void WriteRules(params ResponseRule?[] rules) => File.WriteAllText(PathName,
        JsonSerializer.Serialize(new { Version = 1, Rules = rules }));

    private static string ReadStatus(RuleStore store)
    {
        var method = typeof(RuleStore).GetMethods().SingleOrDefault(method => method.Name == "ActiveRules" && method.GetParameters().Length == 2);
        Assert.NotNull(method);
        object?[] arguments = [RuleScopeKind.Persistence, null];
        _ = method.Invoke(store, arguments);
        Assert.NotNull(arguments[1]);
        return arguments[1]!.GetType().GetProperty("Status")!.GetValue(arguments[1])!.ToString()!;
    }

    private sealed class CompletionFailureJournal(Action beforeFailure) : IActionJournal
    {
        public List<ActionJournalEntry> Entries { get; } = [];
        public bool TryAppend(ActionJournalEntry entry)
        {
            if (entry.Phase == ActionJournalPhase.Prepared)
            {
                Entries.Add(entry);
                return true;
            }
            beforeFailure();
            return false;
        }
        public void MarkUndone(Guid actionId, Guid undoActionId) { }
        public IReadOnlyList<ActionJournalEntry> Read(int max = 200) => Entries;
    }
}
