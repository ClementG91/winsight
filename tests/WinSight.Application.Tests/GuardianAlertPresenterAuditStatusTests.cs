using WinSight.Core;
using WinSight.Persistence;
using WinSight.Response;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class GuardianAlertPresenterAuditStatusTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-guardian-audit-").FullName;
    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void AllowAndRevokeExposeThePreciseAuditRefusalWithoutChangingRules()
    {
        var rules = new RuleStore(Path.Combine(_root, "rules.json"));
        var stored = rules.Add(new ResponseRule(Guid.NewGuid(), RuleScopeKind.Persistence,
            RuleDecision.Allow, RuleDuration.Permanent, DateTimeOffset.UtcNow, Item: "existing"))!;
        var before = File.ReadAllBytes(Path.Combine(_root, "rules.json"));
        var presenter = new GuardianAlertPresenter(rules: rules, journal: new ActionJournal("D:\\invalid\0journal.jsonl"));
        var entry = new AutostartEntry(AutostartVector.RunKey, "Updater",
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run [Registry64]",
            @"D:\fixture.exe", @"D:\fixture.exe", @"D:\fixture.exe", ImageResolutionStatus.Present, SignatureVerdict.Unsigned);
        foreach (var verb in new[] { "Allow", "Revoke" })
        {
            var argumentType = verb == "Allow" ? typeof(AutostartEntry) : typeof(Guid);
            var method = typeof(GuardianAlertPresenter).GetMethod(verb, [argumentType, typeof(ResponseResult).MakeByRefType()]);
            Assert.NotNull(method);
            object?[] arguments = [verb == "Allow" ? entry : stored.Id, null];
            _ = method.Invoke(presenter, arguments);
            var result = Assert.IsType<ResponseResult>(arguments[1]);
            Assert.Equal(ResponseOutcome.Failed, result.Outcome);
            Assert.Contains("Unavailable", result.Detail, StringComparison.Ordinal);
            Assert.Equal(before, File.ReadAllBytes(Path.Combine(_root, "rules.json")));
        }
    }
}
