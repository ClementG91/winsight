using System.Globalization;
using System.Resources;

using WinSight.Application;
using WinSight.Response;

using Xunit;

namespace WinSight.Dashboard.Tests;

[Collection(LocalizationCollection.Name)]
public sealed class ResponseDiagnosticsPresentationTests
{
    private static readonly string[] Languages = ["en", "fr", "es"];
    private static readonly string[] RollbackProofKeys = ["ConfirmedAbsent", "ConfirmedActive", "TargetChanged", "Unconfirmed"];
    private static readonly ResourceManager Resources = new("WinSight.Dashboard.Localization.Strings", typeof(AlertWindow).Assembly);
    private const string TechnicalCanary = "UNTRANSLATED_TECHNICAL_DETAIL_CANARY";

    public static TheoryData<string, ActionJournalWriteStatus> AuditCases
    {
        get
        {
            var cases = new TheoryData<string, ActionJournalWriteStatus>();
            foreach (var language in Languages)
            {
                foreach (var status in Enum.GetValues<ActionJournalWriteStatus>()) { cases.Add(language, status); }
            }
            return cases;
        }
    }

    public static TheoryData<string, RuleStoreStatus> RuleCases
    {
        get
        {
            var cases = new TheoryData<string, RuleStoreStatus>();
            foreach (var language in Languages)
            {
                foreach (var status in Enum.GetValues<RuleStoreStatus>()) { cases.Add(language, status); }
            }
            return cases;
        }
    }

    [Theory]
    [MemberData(nameof(AuditCases))]
    public void EveryAuditStatusHasAnExactLocalizedResourceAndOnlyObservedGapsAreShown(string language, ActionJournalWriteStatus status) => InCulture(language, () =>
    {
        var description = ExactResource("ResponseJournal" + status);
        var storage = new ActionJournalWriteResult(status);
        var result = Result(new() { AuditCompletion = storage });
        var message = AlertWindow.MessageFor(result);
        Assert.Contains(result.ActionId.ToString(), message, StringComparison.Ordinal);
        Assert.DoesNotContain(TechnicalCanary, message, StringComparison.Ordinal);
        var gap = ExactResource("ResponseCompletionGap");
        if (storage.Durable) { Assert.DoesNotContain(gap, message, StringComparison.Ordinal); }
        else
        {
            Assert.Contains(gap, message, StringComparison.Ordinal);
            Assert.Contains(description, message, StringComparison.Ordinal);
        }
    });

    [Theory]
    [MemberData(nameof(RuleCases))]
    public void EveryRuleStatusAndPerCallCounterHasLocalizedMeaning(string language, RuleStoreStatus status) => InCulture(language, () =>
    {
        var description = ExactResource("ResponseRule" + status);
        var result = Result(new() { RuleMutation = new(status, 1234, 2) });
        var message = AlertWindow.MessageFor(result);
        Assert.Contains(description, message, StringComparison.Ordinal);
        Assert.Contains(1234.ToString(LocalizationManager.Instance.Culture), message, StringComparison.Ordinal);
        Assert.Contains(2.ToString(LocalizationManager.Instance.Culture), message, StringComparison.Ordinal);
        var invalid = ExactResource(status == RuleStoreStatus.Written ? "ResponseIgnoredRemoved" : "ResponseIgnoredRetained");
        Assert.Contains(invalid, message, StringComparison.Ordinal);
        Assert.Contains(ExactResource("ResponseFutureRulesInactive"), message, StringComparison.Ordinal);
        Assert.DoesNotContain(TechnicalCanary, message, StringComparison.Ordinal);
    });

    [Theory]
    [InlineData("en")]
    [InlineData("fr")]
    [InlineData("es")]
    public void IndependentReasonsSurviveAuditGapsWithoutInventingOneWhenDurable(string language) => InCulture(language, () =>
    {
        foreach (var completion in new[] { ActionJournalWriteStatus.Appended, ActionJournalWriteStatus.EvidenceRecoveryBlocked })
        {
            var result = Result(new()
            {
                AuditCompletion = new(completion),
                PersistenceReasserted = true,
                ProcessRollbackIncomplete = true,
            });
            var message = AlertWindow.MessageFor(result);
            Assert.Contains(LocalizationManager.Instance.Format("AlertBlockReasserted", result.ActionId), message, StringComparison.Ordinal);
            Assert.Contains(ExactResource("ResponseProcessRollbackIncomplete"), message, StringComparison.Ordinal);
            var gap = ExactResource("ResponseCompletionGap");
            if (completion == ActionJournalWriteStatus.Appended) { Assert.DoesNotContain(gap, message, StringComparison.Ordinal); }
            else { Assert.Contains(gap, message, StringComparison.Ordinal); }
            Assert.DoesNotContain(TechnicalCanary, message, StringComparison.Ordinal);
        }
    });

    [Theory]
    [InlineData("en")]
    [InlineData("fr")]
    [InlineData("es")]
    public void IntentAndCompletionAndRuleAndRollbackRolesStayDistinct(string language) => InCulture(language, () =>
    {
        var result = Result(new()
        {
            AuditIntent = new(ActionJournalWriteStatus.LockTimeout),
            AuditCompletion = new(ActionJournalWriteStatus.RotationFailed),
            RuleMutation = new(RuleStoreStatus.Written, 3, 4),
            AllowRollback = new(ResponseOutcome.TargetChanged, new(RuleStoreStatus.TargetChanged, 5, 6), AllowRollbackState.TargetChanged),
        });
        var message = AlertWindow.MessageFor(result);
        Assert.Contains(ExactResource("ResponseIntentRefused"), message, StringComparison.Ordinal);
        Assert.Contains(ExactResource("ResponseCompletionGap"), message, StringComparison.Ordinal);
        Assert.Contains(ExactResource("ResponseJournalLockTimeout"), message, StringComparison.Ordinal);
        Assert.Contains(ExactResource("ResponseJournalRotationFailed"), message, StringComparison.Ordinal);
        var initial = LocalizedRule(RuleStoreStatus.Written, 3, 4);
        var rollback = LocalizedRule(RuleStoreStatus.TargetChanged, 5, 6);
        Assert.Contains(LocalizationManager.Instance.Format("ResponseRuleMutation", initial), message, StringComparison.Ordinal);
        Assert.Contains(LocalizationManager.Instance.Format("ResponseRollbackStorage", rollback), message, StringComparison.Ordinal);
        Assert.Contains(ExactResource("ResponseRollbackTargetChanged"), message, StringComparison.Ordinal);
        Assert.DoesNotContain(ExactResource("ResponseRollbackConfirmedAbsent"), message, StringComparison.Ordinal);
        Assert.DoesNotContain(ExactResource("ResponseRollbackConfirmedActive"), message, StringComparison.Ordinal);
    });

    [Theory]
    [InlineData("en")]
    [InlineData("fr")]
    [InlineData("es")]
    public void RollbackProofIsConservativeForEveryStateAndUnknownOrInconsistentValues(string language) => InCulture(language, () =>
    {
        var cases = new (AllowRollbackState State, ResponseOutcome Outcome, RuleStoreStatus Storage, string Key)[]
        {
            (AllowRollbackState.ConfirmedAbsent, ResponseOutcome.Succeeded, RuleStoreStatus.Written, "ConfirmedAbsent"),
            (AllowRollbackState.ConfirmedAbsent, ResponseOutcome.TargetNotFound, RuleStoreStatus.TargetNotFound, "ConfirmedAbsent"),
            (AllowRollbackState.ConfirmedActive, ResponseOutcome.Failed, RuleStoreStatus.WriteFailed, "ConfirmedActive"),
            (AllowRollbackState.TargetChanged, ResponseOutcome.TargetChanged, RuleStoreStatus.TargetChanged, "TargetChanged"),
            (AllowRollbackState.Unconfirmed, ResponseOutcome.Failed, RuleStoreStatus.Unavailable, "Unconfirmed"),
            ((AllowRollbackState)999, ResponseOutcome.Failed, RuleStoreStatus.Unavailable, "Unconfirmed"),
            (AllowRollbackState.ConfirmedAbsent, ResponseOutcome.Failed, RuleStoreStatus.Written, "Unconfirmed"),
            (AllowRollbackState.ConfirmedActive, ResponseOutcome.Succeeded, RuleStoreStatus.WriteFailed, "Unconfirmed"),
            (AllowRollbackState.TargetChanged, (ResponseOutcome)999, RuleStoreStatus.TargetChanged, "Unconfirmed"),
            (AllowRollbackState.ConfirmedAbsent, ResponseOutcome.Succeeded, RuleStoreStatus.Unavailable, "Unconfirmed"),
            (AllowRollbackState.ConfirmedActive, ResponseOutcome.Failed, RuleStoreStatus.Unavailable, "Unconfirmed"),
            (AllowRollbackState.TargetChanged, ResponseOutcome.TargetChanged, RuleStoreStatus.Unavailable, "Unconfirmed"),
            (AllowRollbackState.ConfirmedAbsent, ResponseOutcome.Succeeded, (RuleStoreStatus)999, "Unconfirmed"),
        };
        foreach (var item in cases)
        {
            var result = Result(new() { AllowRollback = new(item.Outcome, new(item.Storage), item.State) });
            var message = AlertWindow.MessageFor(result);
            Assert.Contains(ExactResource("ResponseRollback" + item.Key), message, StringComparison.Ordinal);
            foreach (var other in RollbackProofKeys.Where(key => key != item.Key))
            {
                Assert.DoesNotContain(ExactResource("ResponseRollback" + other), message, StringComparison.Ordinal);
            }
        }
    });

    [Theory]
    [InlineData("en")]
    [InlineData("fr")]
    [InlineData("es")]
    public void FutureStatusesAndLegacyDetailNeverLeakProseOrInventReasons(string language) => InCulture(language, () =>
    {
        var unknown = AlertWindow.MessageFor(Result(new()
        {
            AuditCompletion = new((ActionJournalWriteStatus)int.MinValue),
            RuleMutation = new((RuleStoreStatus)int.MinValue),
        }));
        Assert.Contains(ExactResource("ResponseJournalUnknown"), unknown, StringComparison.Ordinal);
        Assert.Contains(ExactResource("ResponseRuleUnknown"), unknown, StringComparison.Ordinal);
        Assert.DoesNotContain("-2147483648", unknown, StringComparison.Ordinal);
        Assert.DoesNotContain("[Response", unknown, StringComparison.Ordinal);
        Assert.DoesNotContain(TechnicalCanary, unknown, StringComparison.Ordinal);
        var legacy = Result(null) with { Detail = PersistenceResponder.ReassertedDetail };
        var legacyMessage = AlertWindow.MessageFor(legacy);
        Assert.Contains(legacy.ActionId.ToString(), legacyMessage, StringComparison.Ordinal);
        Assert.DoesNotContain(PersistenceResponder.ReassertedDetail, legacyMessage, StringComparison.Ordinal);
        Assert.DoesNotContain(LocalizationManager.Instance.Format("AlertBlockReasserted", legacy.ActionId), legacyMessage, StringComparison.Ordinal);
        Assert.DoesNotContain(ExactResource("ResponseCompletionGap"), legacyMessage, StringComparison.Ordinal);
        var failed = Result(null) with { Outcome = ResponseOutcome.Failed };
        var failedMessage = AlertWindow.MessageFor(failed);
        Assert.Contains(failed.ActionId.ToString(), failedMessage, StringComparison.Ordinal);
        Assert.DoesNotContain(TechnicalCanary, failedMessage, StringComparison.Ordinal);
    });

    private static string LocalizedRule(RuleStoreStatus status, int ignored, int retained) =>
        ExactResource("ResponseRule" + status) + " "
        + LocalizationManager.Instance.Format("ResponseIgnoredCount", ignored) + " "
        + ExactResource(status == RuleStoreStatus.Written ? "ResponseIgnoredRemoved" : "ResponseIgnoredRetained") + " "
        + LocalizationManager.Instance.Format("ResponseFutureRulesCount", retained) + " "
        + ExactResource("ResponseFutureRulesInactive");

    private static ResponseResult Result(ResponseDiagnostics? diagnostics) => new(
        Guid.NewGuid(), ResponseActionKind.QuarantinePersistence, ResponseOutcome.PartiallyApplied,
        "fixture", DateTimeOffset.UnixEpoch, false, TechnicalCanary)
    { Diagnostics = diagnostics };

    private static string ExactResource(string key)
    {
        // No parent/invariant fallback: every supported language must own the explanatory resource.
        var culture = LocalizationManager.Instance.CurrentCode == "en" ? CultureInfo.InvariantCulture : LocalizationManager.Instance.Culture;
        var set = Resources.GetResourceSet(culture, true, false);
        var value = set?.GetString(key);
        Assert.False(string.IsNullOrWhiteSpace(value), $"Missing {LocalizationManager.Instance.CurrentCode} resource: {key}");
        Assert.DoesNotContain("[Response", value, StringComparison.Ordinal);
        return value!;
    }

    private static void InCulture(string language, Action body)
    {
        var original = LocalizationManager.Instance.CurrentCode;
        try { LocalizationManager.Instance.SetCulture(language); body(); }
        finally { LocalizationManager.Instance.SetCulture(original); }
    }
}
