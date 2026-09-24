using System.Reflection;

using Xunit;

namespace WinSight.Mcp.Tests;

/// <summary>
/// The MCP server is read-only: it never exposes a way to suspend a process, remove persistence, add
/// a firewall rule, or invoke any other response action. This is an authority-boundary invariant, so
/// it is enforced structurally, not only by the read-only annotations on each tool.
/// </summary>
/// <remarks>
/// A targeted guard, not a proof (RA-06): these walks see WinSight's own IL, and the list below names
/// the response mutators known today. <see cref="McpSideEffectBoundaryTests"/> covers what the list
/// cannot - a mutator added later, a write made straight through the framework or a P/Invoke - at the
/// point where the walk leaves WinSight.
/// </remarks>
public sealed class ResponseIsNotReachableFromMcpTests
{
    /// <summary>
    /// The methods that change the machine or the operator's decisions. MCP may read the action
    /// journal and the rule list (the <c>actions</c> and <c>rules</c> categories); it must never
    /// reach one of these.
    /// </summary>
    private static readonly Dictionary<string, string[]> Mutators = new(StringComparer.Ordinal)
    {
        ["WinSight.Response.ProcessResponder"] = ["Suspend", "Resume", "Terminate"],
        ["WinSight.Response.Win32ProcessController"] = ["SuspendThreads", "ResumeThreads", "TerminateProcess"],
        ["WinSight.Response.RuleStore"] = ["Add", "Remove"],
        ["WinSight.Response.ActionJournal"] = ["TryAppend", "MarkUndone"],
        ["WinSight.Response.Quarantine"] = ["Store", "Remove"],
        ["WinSight.Application.PersistenceResponder"] = ["Block", "Restore"],
        ["WinSight.Application.RegistryAndFilePersistenceMutator"] = ["RemoveIfUnchanged", "RestoreIfFree"],
        ["WinSight.Application.GuardianAlertPresenter"] = ["Allow", "Revoke", "Block", "Restore"],
        ["WinSight.Application.FirewallServiceGateway"] = ["MutateAsync"],
        ["WinSight.Application.Adapters"] = ["RespondToProcess", "RestoreBlocked", "RevokeRule"],
        ["WinSight.Firewall.FirewallPolicyStore"] = ["SaveAsync"],
        ["WinSight.Firewall.FirewallRequestDispatcher"] = ["DispatchAsync"],
    };

    private static readonly Lazy<Assembly[]> WinSightAssemblies = McpRoots.WinSightAssemblies;

    [Fact]
    public void TheMcpAssemblyDoesNotDependOnTheResponseLayer()
    {
        var referenced = typeof(WinSight.Mcp.McpScanService).Assembly
            .GetReferencedAssemblies()
            .Select(name => name.Name);

        Assert.DoesNotContain("WinSight.Response", referenced);
    }

    [Fact]
    public void NoMcpTypeExposesAResponseActionVerb()
    {
        var forbidden = new[]
        {
            "Suspend", "Terminate", "Kill", "Quarantine", "Remove", "Disable", "Enable",
            "AddRule", "Block", "Delete", "Restore", "Apply", "Mutate", "Write",
        };

        var offenders = typeof(WinSight.Mcp.McpScanService).Assembly
            .GetTypes()
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            .Where(method => method.GetCustomAttributes()
                .Any(attribute => attribute.GetType().Name.Contains("McpServerTool", StringComparison.Ordinal)))
            .Where(method => forbidden.Any(verb =>
                method.Name.Contains(verb, StringComparison.OrdinalIgnoreCase)))
            .Select(method => $"{method.DeclaringType?.Name}.{method.Name}")
            .ToArray();

        Assert.Empty(offenders);
    }

    /// <summary>
    /// WS-61. MCP depends on the application layer, which depends on the response layer, so the two
    /// checks above cannot see a path such as a scan category that happens to call a responder. This
    /// walks the IL from every method of the MCP assembly (the SDK activates its types by reflection,
    /// so all of them are roots) and proves no mutator is reachable.
    /// </summary>
    [Fact]
    public void NoMutatorIsReachableFromAnyMcpMethod()
    {
        var graph = new IlCallGraph(WinSightAssemblies.Value).Walk(AllMethodsOf(typeof(McpScanService).Assembly));

        Assert.Empty(graph.Unresolved);
        var reached = graph.Reached.Where(IsMutator).Select(graph.PathTo).ToArray();
        Assert.True(reached.Length == 0, "MCP reaches a mutator:\n" + string.Join("\n", reached));
    }

    [Fact]
    public void TheWalkReachesWhatMcpReallyReads()
    {
        var graph = new IlCallGraph(WinSightAssemblies.Value).Walk(AllMethodsOf(typeof(McpScanService).Assembly));
        var reached = graph.Reached.Select(IlCallGraph.Describe).ToHashSet(StringComparer.Ordinal);

        // Through an async state machine, a lambda and a category table: the paths a naive walk misses.
        Assert.Contains("WinSight.Application.Adapters.Run", reached);
        Assert.Contains("WinSight.Response.ActionJournal.Read", reached);
        Assert.Contains("WinSight.Response.RuleStore.ActiveRules", reached);
        Assert.Contains("WinSight.Application.FirewallServiceGateway.GetViewAsync", reached);
    }

    /// <summary>
    /// The positive control: the same walk from the CLI, which does offer the response verbs, finds
    /// them. Without it a walk that silently stopped early would pass the test above.
    /// </summary>
    [Fact]
    public void TheSameWalkFindsTheMutatorsTheCliOffers()
    {
        var cli = WinSightAssemblies.Value.Single(a => a.GetName().Name == "winsight");
        var graph = new IlCallGraph(WinSightAssemblies.Value).Walk([cli.EntryPoint!]);
        var reached = graph.Reached.Where(IsMutator).Select(IlCallGraph.Describe).ToHashSet(StringComparer.Ordinal);

        Assert.Empty(graph.Unresolved);
        Assert.Contains("WinSight.Response.Win32ProcessController.TerminateProcess", reached);
        Assert.Contains("WinSight.Response.RuleStore.Remove", reached);
        Assert.Contains("WinSight.Application.RegistryAndFilePersistenceMutator.RestoreIfFree", reached);
    }

    private static bool IsMutator(MethodBase method) =>
        method.Module.Assembly.GetName().Name == "WinSight.FirewallService"
        || (method.DeclaringType?.FullName is { } type
            && Mutators.TryGetValue(type, out var names)
            && names.Contains(method.Name, StringComparer.Ordinal));

    private static IEnumerable<MethodBase> AllMethodsOf(Assembly assembly) => McpRoots.AllMethodsOf(assembly);
}
