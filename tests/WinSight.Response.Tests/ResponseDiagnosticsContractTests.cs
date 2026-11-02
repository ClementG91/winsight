using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization;

using WinSight.Response;

using Xunit;

namespace WinSight.Response.Tests;

public sealed class ResponseDiagnosticsContractTests
{
    private static readonly string[] RollbackStates = ["Unconfirmed", "ConfirmedAbsent", "ConfirmedActive", "TargetChanged"];

    [Fact]
    public void DiagnosticsAreAdditiveAndExcludedFromPublicJson()
    {
        // Reflection verifies the additive API without requiring future types to compile on RED.
        var diagnosticsProperty = typeof(ResponseResult).GetProperty("Diagnostics");
        Assert.NotNull(diagnosticsProperty);
        Assert.Equal(7, Assert.Single(typeof(ResponseResult).GetConstructors()).GetParameters().Length);
        Assert.Equal(JsonIgnoreCondition.Always,
            diagnosticsProperty.GetCustomAttribute<JsonIgnoreAttribute>()?.Condition);
        AssertInitOnly(diagnosticsProperty);

        var result = new ResponseResult(Guid.NewGuid(), ResponseActionKind.QuarantinePersistence,
            ResponseOutcome.PartiallyApplied, "fixture", DateTimeOffset.UnixEpoch, true,
            "precise English technical detail retained for CLI/MCP");
        Assert.Null(diagnosticsProperty.GetValue(result));
        var options = new[]
        {
            new JsonSerializerOptions(),
            new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                WriteIndented = true,
            },
        };
        var legacyShape = new
        {
            result.ActionId,
            result.Kind,
            result.Outcome,
            result.Target,
            result.AtUtc,
            result.Reversible,
            result.Detail,
            result.Succeeded,
        };
        var legacyJson = options.Select(option => JsonSerializer.Serialize(legacyShape, option)).ToArray();
        var originalJson = options.Select(option => JsonSerializer.Serialize(result, option)).ToArray();
        var withoutDiagnostics = result with { };
        var diagnostics = PopulatedDiagnostics(diagnosticsProperty.PropertyType);
        diagnosticsProperty.SetValue(result, diagnostics);

        for (var i = 0; i < options.Length; i++)
        {
            var actual = JsonSerializer.Serialize(result, options[i]);
            Assert.Equal(legacyJson[i], originalJson[i]);
            Assert.Equal(legacyJson[i], actual);
            Assert.Equal(originalJson[i], actual);
            var roundTrip = Assert.IsType<ResponseResult>(JsonSerializer.Deserialize<ResponseResult>(actual, options[i]));
            Assert.Null(diagnosticsProperty.GetValue(roundTrip));
            Assert.Equal(result.Detail, roundTrip.Detail);
        }
        var copy = result with { Outcome = ResponseOutcome.Failed };
        Assert.Same(diagnostics, diagnosticsProperty.GetValue(copy));
        Assert.Equal(result.Detail, copy.Detail);
        // Generated record value equality deliberately includes the new informational property.
        Assert.NotEqual(withoutDiagnostics, result);
        Assert.Equal(result, result with { });

        var (id, kind, outcome, target, atUtc, reversible, detail) = result;
        Assert.Equal(result.ActionId, id);
        Assert.Equal(result.Kind, kind);
        Assert.Equal(result.Outcome, outcome);
        Assert.Equal(result.Target, target);
        Assert.Equal(result.AtUtc, atUtc);
        Assert.Equal(result.Reversible, reversible);
        Assert.Equal(result.Detail, detail);
    }

    [Fact]
    public void DiagnosticsCarryObservedValuesAndIndependentReasonsWithAnUnconfirmedDefault()
    {
        var diagnosticsProperty = typeof(ResponseResult).GetProperty("Diagnostics");
        Assert.NotNull(diagnosticsProperty);
        var type = diagnosticsProperty.PropertyType;
        Assert.Equal("WinSight.Response.ResponseDiagnostics", type.FullName);
        Assert.True(type.IsSealed);
        var diagnostics = PopulatedDiagnostics(type);
        Assert.True(Assert.IsType<bool>(type.GetProperty("PersistenceReasserted")!.GetValue(diagnostics)));
        Assert.True(Assert.IsType<bool>(type.GetProperty("ProcessRollbackIncomplete")!.GetValue(diagnostics)));
        var rule = Assert.IsType<RuleStoreResult>(type.GetProperty("RuleMutation")!.GetValue(diagnostics));
        Assert.Equal(RuleStoreStatus.UnsupportedIdentityCollision, rule.Status);
        Assert.Equal(2, rule.IgnoredEntries);
        Assert.Equal(3, rule.RetainedUnsupportedEntries);
        Assert.Equal(ActionJournalWriteStatus.Appended,
            Assert.IsType<ActionJournalWriteResult>(type.GetProperty("AuditIntent")!.GetValue(diagnostics)).Status);
        Assert.Equal(ActionJournalWriteStatus.EvidenceRecoveryBlocked,
            Assert.IsType<ActionJournalWriteResult>(type.GetProperty("AuditCompletion")!.GetValue(diagnostics)).Status);

        var state = typeof(ResponseResult).Assembly.GetType("WinSight.Response.AllowRollbackState", throwOnError: true)!;
        Assert.Equal("Unconfirmed", Enum.GetName(state, Activator.CreateInstance(state)!));
        Assert.Equal(RollbackStates, Enum.GetNames(state));
        var rollback = type.GetProperty("AllowRollback")!.GetValue(diagnostics)!;
        Assert.Equal(ResponseOutcome.TargetChanged, rollback.GetType().GetProperty("Outcome")!.GetValue(rollback));
        var rollbackStorage = Assert.IsType<RuleStoreResult>(rollback.GetType().GetProperty("Storage")!.GetValue(rollback));
        Assert.NotSame(rule, rollbackStorage);
        Assert.Equal(RuleStoreStatus.TargetChanged, rollbackStorage.Status);
        Assert.Equal(5, rollbackStorage.IgnoredEntries);
        Assert.Equal(6, rollbackStorage.RetainedUnsupportedEntries);
        Assert.Equal("TargetChanged", rollback.GetType().GetProperty("State")!.GetValue(rollback)!.ToString());
        foreach (var property in type.GetProperties(BindingFlags.Instance | BindingFlags.Public))
        {
            AssertInitOnly(property);
        }
        foreach (var property in rollback.GetType().GetProperties(BindingFlags.Instance | BindingFlags.Public))
        {
            AssertInitOnly(property);
        }
    }

    private static object PopulatedDiagnostics(Type type)
    {
        var diagnostics = Activator.CreateInstance(type)!;
        Set(diagnostics, "AuditIntent", new ActionJournalWriteResult(ActionJournalWriteStatus.Appended));
        Set(diagnostics, "AuditCompletion", new ActionJournalWriteResult(ActionJournalWriteStatus.EvidenceRecoveryBlocked));
        var rule = new RuleStoreResult(RuleStoreStatus.UnsupportedIdentityCollision, 2, 3);
        Set(diagnostics, "RuleMutation", rule);
        Set(diagnostics, "PersistenceReasserted", true);
        Set(diagnostics, "ProcessRollbackIncomplete", true);
        var rollback = type.GetProperty("AllowRollback")!;
        var state = typeof(ResponseResult).Assembly.GetType("WinSight.Response.AllowRollbackState", throwOnError: true)!;
        Set(diagnostics, "AllowRollback", Activator.CreateInstance(rollback.PropertyType,
            new object[] { ResponseOutcome.TargetChanged, new RuleStoreResult(RuleStoreStatus.TargetChanged, 5, 6), Enum.Parse(state, "TargetChanged") })!);
        return diagnostics;
    }

    private static void Set(object target, string name, object value)
    {
        var property = target.GetType().GetProperty(name);
        Assert.NotNull(property);
        Assert.Equal(value.GetType(), property.PropertyType);
        AssertInitOnly(property);
        property.SetValue(target, value);
        Assert.Equal(value, property.GetValue(target));
    }

    private static void AssertInitOnly(PropertyInfo property)
    {
        Assert.NotNull(property.SetMethod);
        Assert.True(property.SetMethod.IsPublic);
        Assert.Contains(typeof(IsExternalInit), property.SetMethod.ReturnParameter.GetRequiredCustomModifiers());
    }
}
