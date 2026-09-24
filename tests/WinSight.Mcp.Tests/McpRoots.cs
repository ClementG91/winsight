using System.Reflection;

namespace WinSight.Mcp.Tests;

/// <summary>The assemblies and roots every MCP reachability walk starts from.</summary>
internal static class McpRoots
{
    private const BindingFlags Declared = BindingFlags.Public | BindingFlags.NonPublic
        | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    /// <summary>WinSight's product assemblies beside the tests, without the test assemblies.</summary>
    public static readonly Lazy<Assembly[]> WinSightAssemblies = new(() => Directory
        .GetFiles(AppContext.BaseDirectory, "*.dll")
        .Where(path => !Path.GetFileName(path).Contains(".Tests", StringComparison.Ordinal))
        .Select(AssemblyName.GetAssemblyName)
        .Where(IlCallGraph.IsWinSight)
        .Select(Assembly.Load)
        .ToArray());

    /// <summary>
    /// Every method and constructor of an assembly. The MCP SDK activates tool types by reflection,
    /// so all of them are roots, not only the tool methods.
    /// </summary>
    public static IEnumerable<MethodBase> AllMethodsOf(Assembly assembly) =>
        assembly.GetTypes().SelectMany(type => type.GetMethods(Declared).Cast<MethodBase>()
            .Concat(type.GetConstructors(Declared)));
}
