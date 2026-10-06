using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

using WinSight.Core;
using WinSight.Persistence;
using WinSight.Response;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class RollbackRuleStoreTests : IDisposable
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-rollback-version-").FullName;
    private string PathName => Path.Combine(_root, "rules.json");
    private RuleStore Store => new(PathName);
    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Theory]
    [InlineData("expired", false)]
    [InlineData("expired", true)]
    [InlineData("item", false)]
    [InlineData("item", true)]
    [InlineData("decision", false)]
    [InlineData("decision", true)]
    [InlineData("extension", false)]
    [InlineData("extension", true)]
    [InlineData("formatting", false)]
    [InlineData("formatting", true)]
    [InlineData("duplicate", false)]
    [InlineData("duplicate", true)]
    [InlineData("future", false)]
    [InlineData("future", true)]
    [InlineData("keyless-duplicate", false)]
    [InlineData("keyless-duplicate", true)]
    [InlineData("required-duplicate", false)]
    [InlineData("required-duplicate", true)]
    [InlineData("keyless-replacement", false)]
    [InlineData("keyless-replacement", true)]
    [InlineData("required-replacement", false)]
    [InlineData("required-replacement", true)]
    [InlineData("escaped-id-duplicate", false)]
    [InlineData("escaped-id-duplicate", true)]
    public void ChangedAllowRollbackPreservesTheReplacement(string change, bool denyCreation)
    {
        var directory = new DirectoryInfo(_root);
        var originalAcl = directory.GetAccessControl().GetSecurityDescriptorBinaryForm();
        byte[]? replacementBytes = null;
        Guid? originalId = null;
        var journal = new CompletionFailureJournal(() =>
        {
            var originalRule = Assert.Single(Store.ActiveRules(RuleScopeKind.Persistence));
            originalId = originalRule.Id;
            Replace(originalRule, change);
            replacementBytes = File.ReadAllBytes(PathName);
            if (denyCreation)
            {
                DenyCreation(directory);
            }
        });
        try
        {
            var presenter = new GuardianAlertPresenter(rules: Store, journal: journal);
            var returned = presenter.Allow(Entry(), out var result);

            Assert.NotNull(replacementBytes);
            Assert.Equal(replacementBytes, File.ReadAllBytes(PathName));
            Assert.Null(returned);
            Assert.Equal(ResponseOutcome.PartiallyApplied, result.Outcome);
            Assert.False(result.Reversible);
            Assert.Contains("TargetChanged", result.Detail, StringComparison.Ordinal);
            Assert.Contains("replacement was preserved", result.Detail, StringComparison.Ordinal);
            Assert.DoesNotContain("rule remains active", result.Detail, StringComparison.Ordinal);
            Assert.DoesNotContain("confirmed absent", result.Detail, StringComparison.Ordinal);
            var prepared = Assert.Single(journal.Entries);
            Assert.Equal(originalId, prepared.ActionId);
            Assert.Equal(ActionJournalPhase.Prepared, prepared.Phase);
            Assert.Equal(ResponseActionKind.AddRule, prepared.Kind);
            Assert.Empty(journal.UndoCalls);
        }
        finally
        {
            Restore(directory, originalAcl);
        }
        Assert.Equal(replacementBytes, File.ReadAllBytes(PathName));
    }

    [Fact]
    public void ConditionalRollbackRemovesOnlyItsExactUnchangedRule()
    {
        var expected = Rule();
        var neighbor = Rule() with { Item = "run:neighbor" };
        Assert.NotNull(Store.Add(expected));
        Assert.NotNull(Store.Add(neighbor));

        var outcome = ConditionalRemove(Store, expected, out var result, out var active);

        Assert.Equal(ResponseOutcome.Succeeded, outcome);
        Assert.True(result.Durable);
        Assert.False(active);
        Assert.Equal(neighbor, Assert.Single(Store.ActiveRules(RuleScopeKind.Persistence)));
        Assert.Equal(ResponseOutcome.TargetNotFound, ConditionalRemove(Store, expected, out result, out active));
        Assert.Equal("TargetNotFound", result.Status.ToString());
        Assert.False(active);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RefusedExactRollbackReportsObservedActivityFromTheStoreClock(bool expire)
    {
        var observedNow = new DateTimeOffset(2026, 10, 6, 0, 0, 0, TimeSpan.Zero);
        var store = new RuleStore(PathName, () => observedNow);
        var expected = Rule() with { Duration = RuleDuration.Timed, CreatedUtc = observedNow, ExpiresUtc = observedNow.AddMinutes(1) };
        Assert.NotNull(store.Add(expected));
        var before = File.ReadAllBytes(PathName);
        if (expire)
        {
            observedNow = observedNow.AddMinutes(2);
        }
        var directory = new DirectoryInfo(_root);
        var originalAcl = directory.GetAccessControl().GetSecurityDescriptorBinaryForm();
        try
        {
            DenyCreation(directory);

            Assert.Equal(ResponseOutcome.Failed, ConditionalRemove(store, expected, out var result, out var active));

            Assert.Equal("WriteFailed", result.Status.ToString());
            Assert.False(result.Durable);
            Assert.Equal(!expire, active);
            Assert.Equal(before, File.ReadAllBytes(PathName));
        }
        finally
        {
            Restore(directory, originalAcl);
        }
        Assert.Equal(before, File.ReadAllBytes(PathName));
    }

    [Theory]
    [InlineData("extension")]
    [InlineData("formatting")]
    [InlineData("duplicate")]
    public void ConditionalRollbackDoesNotCleanInvalidNeighborsOnAnIdentityRefusal(string change)
    {
        var expected = Rule();
        Assert.NotNull(Store.Add(expected));
        Replace(expected, change);
        var text = File.ReadAllText(PathName);
        File.WriteAllText(PathName, text[..text.LastIndexOf(']')] + ",null" + text[text.LastIndexOf(']')..]);
        var before = File.ReadAllBytes(PathName);

        Assert.Equal(ResponseOutcome.TargetChanged, ConditionalRemove(Store, expected, out var result, out var active));

        Assert.Equal("TargetChanged", result.Status.ToString());
        Assert.Equal(1, result.IgnoredEntries);
        Assert.False(result.Durable);
        Assert.False(active);
        Assert.Equal(before, File.ReadAllBytes(PathName));
    }

    [Fact]
    public void OversizedExpectedRuleCannotRequestUnboundedRollbackSerialization()
    {
        var expected = Rule();
        Assert.NotNull(Store.Add(expected));
        var before = File.ReadAllBytes(PathName);

        Assert.Equal(ResponseOutcome.Failed, ConditionalRemove(Store,
            expected with { Item = new string('x', 9 * 1024 * 1024) }, out var result, out var active));

        Assert.Equal("ByteLimit", result.Status.ToString());
        Assert.False(active);
        Assert.Equal(before, File.ReadAllBytes(PathName));
    }

    [Fact]
    public void ExplicitRevocationStillRemovesEveryEntryWithTheConfirmedIdentity()
    {
        var expected = Rule();
        Assert.NotNull(Store.Add(expected));
        Replace(expected, "duplicate");
        var journal = new RecordingJournal();
        var presenter = new GuardianAlertPresenter(rules: Store, journal: journal);

        Assert.Equal(ResponseOutcome.Succeeded, presenter.Revoke(expected.Id, out var result));

        Assert.Equal(ResponseOutcome.Succeeded, result.Outcome);
        Assert.Empty(Store.ActiveRules(RuleScopeKind.Persistence));
        Assert.Equal(2, journal.Entries.Count);
        Assert.Equal(ActionJournalPhase.Prepared, journal.Entries[0].Phase);
        Assert.Equal(ActionJournalPhase.Completed, journal.Entries[1].Phase);
        var undo = Assert.Single(journal.UndoCalls);
        Assert.Equal(expected.Id, undo.RuleId);
        Assert.Equal(journal.Entries[0].ActionId, undo.UndoId);
    }

    private void Replace(ResponseRule original, string change)
    {
        var replacement = change switch
        {
            "expired" => original with { Duration = RuleDuration.Timed, ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(-1) },
            "item" => original with { Item = "run:operator-replacement" },
            "decision" => original with { Decision = RuleDecision.Block },
            _ => original,
        };
        if (change is "expired" or "item" or "decision")
        {
            Assert.NotNull(Store.Add(replacement));
            return;
        }
        var node = JsonSerializer.SerializeToNode(original)!;
        if (change.StartsWith("keyless", StringComparison.Ordinal))
        {
            node["Item"] = null;
            node["ImagePath"] = null;
            node["ImageSha256"] = null;
            node["Publisher"] = null;
        }
        if (change.StartsWith("required", StringComparison.Ordinal))
        {
            Assert.True(node.AsObject().Remove("Decision"));
        }
        if (change == "extension")
        {
            node["FutureExtension"] = JsonSerializer.SerializeToNode(new { Value = "operator data", Number = 1 });
        }
        if (change == "future")
        {
            node["Scope"] = 99;
        }
        var raw = change == "formatting"
            ? JsonSerializer.Serialize(original, Indented) : node.ToJsonString();
        if (change == "escaped-id-duplicate")
        {
            raw = "{\"\\u0049d\":\"" + original.Id + "\"," + raw[1..];
        }
        if (change is "keyless-duplicate" or "required-duplicate")
        {
            raw = JsonSerializer.Serialize(original) + "," + raw;
        }
        File.WriteAllText(PathName, "{\"Version\":1,\"Rules\":[" + raw + (change == "duplicate" ? "," + raw : string.Empty) + "]}");
    }

    private static ResponseOutcome ConditionalRemove(RuleStore store, ResponseRule expected,
        out RuleStoreResult result, out bool active)
    {
        var method = typeof(RuleStore).GetMethod("RemoveIfUnchanged", BindingFlags.Instance | BindingFlags.Public);
        Assert.NotNull(method);
        object?[] arguments = [expected, null, false];
        var outcome = Assert.IsType<ResponseOutcome>(method.Invoke(store, arguments));
        result = Assert.IsType<RuleStoreResult>(arguments[1]);
        active = Assert.IsType<bool>(arguments[2]);
        return outcome;
    }

    private static void DenyCreation(DirectoryInfo directory)
    {
        var denied = directory.GetAccessControl();
        denied.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!,
            FileSystemRights.CreateFiles, AccessControlType.Deny));
        directory.SetAccessControl(denied);
    }
    private static void Restore(DirectoryInfo directory, byte[] originalAcl)
    {
        var restored = new DirectorySecurity();
        restored.SetSecurityDescriptorBinaryForm(originalAcl, AccessControlSections.Access);
        directory.SetAccessControl(restored);
    }
    private static ResponseRule Rule() => new(Guid.NewGuid(), RuleScopeKind.Persistence, RuleDecision.Allow,
        RuleDuration.Permanent, DateTimeOffset.UtcNow, Item: "run:original");
    private static AutostartEntry Entry() => new(AutostartVector.RunKey, "Updater",
        @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run [Registry64]",
        @"D:\u.exe", @"D:\u.exe", @"D:\u.exe", ImageResolutionStatus.Present, SignatureVerdict.Unsigned);

    private sealed class CompletionFailureJournal(Action callback) : RecordingJournal
    {
        public override bool TryAppend(ActionJournalEntry entry)
        {
            if (entry.Phase == ActionJournalPhase.Completed)
            {
                callback();
                return false;
            }
            return base.TryAppend(entry);
        }
    }
    private class RecordingJournal : IActionJournal
    {
        public List<ActionJournalEntry> Entries { get; } = [];
        public List<(Guid RuleId, Guid UndoId)> UndoCalls { get; } = [];
        public virtual bool TryAppend(ActionJournalEntry entry) { Entries.Add(entry); return true; }
        public void MarkUndone(Guid actionId, Guid undoActionId) => UndoCalls.Add((actionId, undoActionId));
        public IReadOnlyList<ActionJournalEntry> Read(int max = 200) => Entries;
    }
}
