using System.Text;
using System.Text.Json;

using Microsoft.Win32;

using WinSight.Application;
using WinSight.Core;
using WinSight.Persistence;
using WinSight.Response;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class ResponseLongLabelTests : IDisposable
{
    private readonly string _subKey = $@"Software\WinSight.Tests\LongLabels\{Guid.NewGuid():N}";
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-long-label-").FullName;

    public void Dispose()
    {
        Registry.CurrentUser.DeleteSubKeyTree(_subKey, throwOnMissingSubKey: false);
        Directory.Delete(_root, recursive: true);
    }

    [Theory]
    [InlineData("ascii", true)]
    [InlineData("html", true)]
    [InlineData("unicode", true)]
    [InlineData("emoji", true)]
    [InlineData("controls", true)]
    [InlineData("ascii", false)]
    [InlineData("html", false)]
    [InlineData("unicode", false)]
    [InlineData("emoji", false)]
    [InlineData("controls", false)]
    public void LongRegistryNamesRemainActionable(string nameKind, bool useTransactions)
    {
        var name = nameKind switch
        {
            "ascii" => new string('A', 16_383),
            "html" => new string('<', 2_800),
            "unicode" => new string('\u0436', 2_800),
            "emoji" => string.Concat(Enumerable.Repeat("\U0001F600", 4_000)),
            _ => string.Concat(Enumerable.Repeat("name\r\n\t\u202e\u2066", 300)),
        };
        const string command = @"D:\WinSight.Tests\nonexistent.exe --fixture";
        using (var key = Registry.CurrentUser.CreateSubKey(_subKey))
        {
            key.SetValue(name, command, RegistryValueKind.ExpandString);
        }
        var entry = new AutostartEntry(AutostartVector.RunKey, name,
            $@"HKCU\{_subKey} [Registry64]", command, command, command,
            ImageResolutionStatus.Present, SignatureVerdict.Unsigned);
        var journalPath = Path.Combine(_root, "journal.jsonl");
        var rules = new RuleStore(Path.Combine(_root, "rules.json"));
        var presenter = new GuardianAlertPresenter(new RegistryAndFilePersistenceMutator(useTransactions),
            new Quarantine(Path.Combine(_root, "quarantine")), rules, new ActionJournal(journalPath));

        var block = presenter.Block(entry);
        Assert.Equal(ResponseOutcome.Succeeded, block.Outcome);
        using (var key = Registry.CurrentUser.OpenSubKey(_subKey))
        {
            Assert.Null(key!.GetValue(name));
        }
        Assert.Equal(ResponseOutcome.Succeeded, presenter.Restore(block.ActionId).Outcome);
        using (var key = Registry.CurrentUser.OpenSubKey(_subKey))
        {
            Assert.Equal(command, key!.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames));
            Assert.Equal(RegistryValueKind.ExpandString, key.GetValueKind(name));
        }
        var rule = Assert.IsType<ResponseRule>(presenter.Allow(entry));
        Assert.Equal(PersistenceActionResolver.Resolve(entry)!.RuleItemKey, rule.Item);
        Assert.Equal(rule.Id, presenter.SuppressingRule(entry)!.Id);
        Assert.Equal(ResponseOutcome.Succeeded, presenter.Revoke(rule.Id));
        Assert.Null(presenter.SuppressingRule(entry));

        foreach (var line in File.ReadAllLines(journalPath))
        {
            Assert.True(Encoding.UTF8.GetByteCount(line) + 1 <= 16 * 1024);
            var recorded = JsonSerializer.Deserialize<ActionJournalEntry>(line)!;
            Assert.True(recorded.Target.Length <= 2048);
            AssertValidUtf16(recorded.Target);
        }
        var history = new ActionJournal(journalPath).Read();
        Assert.Contains(history, row => row.Kind == ResponseActionKind.QuarantinePersistence
            && row.Target.Contains("[truncated sha256:", StringComparison.Ordinal));
    }

    [Fact]
    public void TruncatedLabelsKeepDistinctFullTextDigestsAndValidSurrogates()
    {
        var path = Path.Combine(_root, "digests.jsonl");
        var journal = new ActionJournal(path);
        var prefix = "A" + string.Concat(Enumerable.Repeat("\U0001F600", 3000));
        var targets = new[] { prefix + "first", prefix + "second" };
        foreach (var target in targets)
        {
            Assert.True(journal.TryAppend(new ActionJournalEntry(Guid.NewGuid(), ResponseActionKind.AddRule,
                ResponseOutcome.Succeeded, target, DateTimeOffset.UtcNow, true)));
        }
        var rows = journal.Read();
        Assert.Equal(2, rows.Count);
        Assert.NotEqual(rows[0].Target, rows[1].Target);
        foreach (var row in rows)
        {
            Assert.True(row.Target.Length <= 2048);
            Assert.Contains("[truncated sha256:", row.Target, StringComparison.Ordinal);
            AssertValidUtf16(row.Target);
        }
    }

    private static void AssertValidUtf16(string text)
    {
        for (var i = 0; i < text.Length; i++)
        {
            if (char.IsHighSurrogate(text[i]))
            {
                Assert.True(i + 1 < text.Length && char.IsLowSurrogate(text[++i]));
            }
            else
            {
                Assert.False(char.IsLowSurrogate(text[i]));
            }
        }
    }
}
