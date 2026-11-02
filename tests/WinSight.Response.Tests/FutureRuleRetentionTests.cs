using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

using Xunit;

namespace WinSight.Response.Tests;

public sealed class FutureRuleRetentionTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-future-rules-").FullName;
    private string PathName => Path.Combine(_root, "rules.json");
    private RuleStore Store => new(PathName);
    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Theory]
    [InlineData(99, 0, 4)]
    [InlineData(0, 99, 4)]
    [InlineData(0, 0, 99)]
    [InlineData(99, 0, 0)]
    public void FutureRuleBytesSurviveNeighborAddAndRemove(int scope, int decision, int duration)
    {
        var id = Guid.NewGuid();
        var raw = Raw(id, scope, decision, duration);
        Write(raw);
        var before = File.ReadAllBytes(PathName);
        Assert.Empty(Store.ActiveRules((RuleScopeKind)scope));
        Assert.Null(Store.Match((RuleScopeKind)scope, item: "run:updater"));
        Assert.Equal(before, File.ReadAllBytes(PathName));
        var neighbor = Rule();

        Assert.NotNull(Store.Add(neighbor));

        Assert.Equal(Encoding.UTF8.GetBytes(raw), RawBytes(id));
        Assert.Equal(neighbor.Id, Assert.Single(Store.ActiveRules(RuleScopeKind.Persistence, out var read)).Id);
        Assert.Equal(0, read.IgnoredEntries);
        Assert.Equal(1, Retained(read));
        Assert.Contains("retained", read.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("invalid entries were removed", read.Detail, StringComparison.Ordinal);
        Assert.Equal(ResponseOutcome.Succeeded, Store.RemoveWithOutcome(neighbor.Id));
        Assert.Equal(Encoding.UTF8.GetBytes(raw), RawBytes(id));
        Assert.Empty(Store.ActiveRules((RuleScopeKind)scope));
        Assert.Null(Store.Match((RuleScopeKind)scope, item: "run:updater"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ANewRuleCannotOverwriteAnyRetainedFutureIdentity(bool knownDuplicate)
    {
        var id = Guid.NewGuid();
        var known = Rule() with { Id = id };
        Write(knownDuplicate ? [Raw(id), JsonSerializer.Serialize(known)] : [Raw(id)]);
        var before = File.ReadAllBytes(PathName);

        Assert.Null(Store.Add(known, out var result));

        Assert.Equal("UnsupportedIdentityCollision", result.Status.ToString());
        Assert.False(result.Durable);
        Assert.Equal(before, File.ReadAllBytes(PathName));
    }

    [Fact]
    public void ExplicitRemovalCanRevokeAFutureIdentityWithoutRewritingItsNeighbors()
    {
        var id = Guid.NewGuid();
        var neighbor = Guid.NewGuid();
        var raw = Raw(neighbor, decision: 99);
        Write(Raw(id), raw);

        Assert.Equal(ResponseOutcome.Succeeded, Store.RemoveWithOutcome(id, out var result));

        Assert.True(result.Durable);
        Assert.Equal(1, Retained(result));
        Assert.Equal(Encoding.UTF8.GetBytes(raw), RawBytes(neighbor));
        Assert.Equal(ResponseOutcome.TargetNotFound, Store.RemoveWithOutcome(id));
    }

    [Fact]
    public void KnownRuleExtensionBytesAlsoSurviveNeighborWrites()
    {
        var id = Guid.NewGuid();
        var raw = Raw(id, scope: 0);
        Write(raw);
        var neighbor = Rule();
        Assert.NotNull(Store.Add(neighbor));
        Assert.Equal(Encoding.UTF8.GetBytes(raw), RawBytes(id));
        Assert.Equal(ResponseOutcome.Succeeded, Store.RemoveWithOutcome(neighbor.Id));
        Assert.Equal(Encoding.UTF8.GetBytes(raw), RawBytes(id));
    }

    [Fact]
    public void FutureEntriesConsumeTheEntireRawRuleBudget()
    {
        Write(Enumerable.Range(0, 8192).Select(_ => Raw(Guid.NewGuid())).ToArray());
        var before = File.ReadAllBytes(PathName);
        Assert.Null(Store.Add(Rule(), out var result));
        Assert.Equal("RuleLimit", result.Status.ToString());
        Assert.Equal(before, File.ReadAllBytes(PathName));
        File.WriteAllText(PathName, "{\"Version\":1,\"Rules\":[" + string.Join(',', Enumerable.Repeat("null", 8193)) + "]}");
        before = File.ReadAllBytes(PathName);
        Assert.Null(Store.Add(Rule(), out result));
        Assert.Equal("RuleLimit", result.Status.ToString());
        Assert.Equal(before, File.ReadAllBytes(PathName));
    }

    [Fact]
    public void PreservedFutureBytesCannotBeDiscardedToFitTheOutputBudget()
    {
        const int maxBytes = 8 * 1024 * 1024;
        var raw = Raw(Guid.NewGuid());
        var padded = raw[..^1] + ",\"Padding\":\"";
        var suffix = "\"}";
        var envelope = "{\"Version\":1,\"Rules\":[";
        var padding = maxBytes - 64 - Encoding.UTF8.GetByteCount(envelope + padded + suffix + "]}");
        Write(padded + new string('a', padding) + suffix);
        var before = File.ReadAllBytes(PathName);
        Assert.Equal(maxBytes - 64, before.Length);

        Assert.Null(Store.Add(Rule() with { Item = new string('b', 1024) }, out var result));

        Assert.Equal("ByteLimit", result.Status.ToString());
        Assert.Equal(before, File.ReadAllBytes(PathName));
    }

    [Theory]
    [InlineData("Decision", "99", "0")]
    [InlineData("Sc\\u006fpe", "99", "0")]
    public void DuplicateDecodedSemanticFieldsCannotInventAnActiveRule(string name, string first, string last)
    {
        var raw = Raw(Guid.NewGuid(), scope: 0);
        var canonical = name == "Decision" ? "Decision" : "Scope";
        raw = raw.Replace($"\"{canonical}\" : 0", $"\"{name}\":{first},\"{canonical}\":{last}", StringComparison.Ordinal);
        Write(raw);
        var before = File.ReadAllBytes(PathName);
        Assert.Empty(Store.ActiveRules(RuleScopeKind.Persistence, out var result));
        Assert.Equal(1, result.IgnoredEntries);
        Assert.Equal(before, File.ReadAllBytes(PathName));
        var neighbor = Rule();
        Assert.NotNull(Store.Add(neighbor));
        Assert.Equal(0, Retained(ReadResult()));
        Assert.Equal(neighbor.Id, Assert.Single(Store.ActiveRules(RuleScopeKind.Persistence)).Id);
    }

    [Fact]
    public void OversizedNewRuleTextIsRefusedWithoutRewritingTheStore()
    {
        Write();
        var before = File.ReadAllBytes(PathName);
        Assert.Null(Store.Add(Rule() with { Item = new string('x', 9 * 1024 * 1024) }, out var result));
        Assert.Equal("ByteLimit", result.Status.ToString());
        Assert.Equal(before, File.ReadAllBytes(PathName));
    }

    [Theory]
    [InlineData("null")]
    [InlineData("keyless")]
    [InlineData("required")]
    [InlineData("wrong-type")]
    [InlineData("empty-id")]
    [InlineData("timed")]
    [InlineData("once")]
    [InlineData("reboot")]
    [InlineData("process")]
    public void GenuinelyInvalidEntriesRemainVisibleAndAreRemovedOnlyByASuccessfulWrite(string defect)
    {
        var raw = Raw(Guid.NewGuid(), scope: 0);
        raw = defect switch
        {
            "null" => "null",
            "keyless" => raw.Replace("run:\\u0075pdater", string.Empty, StringComparison.Ordinal),
            "required" => raw.Replace("\"Decision\" : 0,", string.Empty, StringComparison.Ordinal),
            "wrong-type" => raw.Replace("\"Scope\" : 0", "\"Scope\":\"unknown\"", StringComparison.Ordinal),
            "empty-id" => raw.Replace(raw.Substring(raw.IndexOf("\"Id\"", StringComparison.Ordinal) + 8, 36), Guid.Empty.ToString(), StringComparison.Ordinal),
            "timed" => raw.Replace("\"Duration\" : 4", "\"Duration\":3", StringComparison.Ordinal),
            "once" => raw.Replace("\"Duration\" : 4", "\"Duration\":0", StringComparison.Ordinal),
            "reboot" => raw.Replace("\"Duration\" : 4", "\"Duration\":1", StringComparison.Ordinal),
            "process" => raw.Replace("\"Duration\" : 4", "\"Duration\":2", StringComparison.Ordinal),
            _ => throw new ArgumentOutOfRangeException(nameof(defect)),
        };
        Write(raw);
        var before = File.ReadAllBytes(PathName);
        Assert.Empty(Store.ActiveRules(RuleScopeKind.Persistence, out var result));
        Assert.Equal(1, result.IgnoredEntries);
        Assert.Equal(before, File.ReadAllBytes(PathName));
        var neighbor = Rule();
        Assert.NotNull(Store.Add(neighbor));
        Assert.Equal(neighbor.Id, Assert.Single(Store.ActiveRules(RuleScopeKind.Persistence)).Id);
        Assert.Equal(0, ReadResult().IgnoredEntries);
    }

    [Fact]
    public void RefusedFutureRemovalReportsTheEntriesStillPresentOnDisk()
    {
        var id = Guid.NewGuid();
        Write(Raw(id));
        Assert.NotNull(Store.Add(Rule())); // Establish the writer sidecar before denying creation.
        var before = File.ReadAllBytes(PathName);
        var directory = new DirectoryInfo(_root);
        var original = directory.GetAccessControl().GetSecurityDescriptorBinaryForm();
        var denied = directory.GetAccessControl();
        denied.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!,
            FileSystemRights.CreateFiles, AccessControlType.Deny));
        try
        {
            directory.SetAccessControl(denied);
            Assert.Equal(ResponseOutcome.Failed, Store.RemoveWithOutcome(id, out var result));
            Assert.Equal("WriteFailed", result.Status.ToString());
            Assert.Equal(1, Retained(result));
            Assert.Equal(before, File.ReadAllBytes(PathName));
        }
        finally
        {
            var restored = new DirectorySecurity();
            restored.SetSecurityDescriptorBinaryForm(original, AccessControlSections.Access);
            directory.SetAccessControl(restored);
        }
        Assert.Equal(before, File.ReadAllBytes(PathName));
        Assert.Equal(1, Retained(ReadResult()));
    }

    private RuleStoreResult ReadResult()
    {
        Store.ActiveRules(RuleScopeKind.Persistence, out var result);
        return result;
    }

    private static int Retained(RuleStoreResult result)
    {
        var property = typeof(RuleStoreResult).GetProperty("RetainedUnsupportedEntries");
        Assert.NotNull(property);
        return Assert.IsType<int>(property.GetValue(result));
    }

    private byte[] RawBytes(Guid id)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(PathName));
        var found = document.RootElement.GetProperty("Rules").EnumerateArray()
            .SingleOrDefault(value => value.GetProperty("Id").GetGuid() == id);
        Assert.Equal(JsonValueKind.Object, found.ValueKind);
        return Encoding.UTF8.GetBytes(found.GetRawText());
    }

    private void Write(params string[] entries) => File.WriteAllText(PathName, "{\"Version\":1,\"Rules\":[" + string.Join(',', entries) + "]}");
    private static ResponseRule Rule() => new(Guid.NewGuid(), RuleScopeKind.Persistence, RuleDecision.Allow,
        RuleDuration.Permanent, DateTimeOffset.UtcNow, Item: "run:neighbor");
    private static string Raw(Guid id, int scope = 99, int decision = 0, int duration = 4) =>
        $$"""
        { "Id" : "{{id}}", "Scope" : {{scope}}, "Decision" : {{decision}}, "Duration" : {{duration}},
          "CreatedUtc":"2026-10-06T00:00:00+00:00", "Item":"run:\u0075pdater",
          "Extension" : {"number":1e0,"nested":[true,null,{"text":"\u0061"}]} }
        """;
}
