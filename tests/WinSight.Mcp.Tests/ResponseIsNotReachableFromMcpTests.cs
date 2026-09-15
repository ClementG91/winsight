using System.Reflection;

using Xunit;

namespace WinSight.Mcp.Tests;

/// <summary>
/// The MCP server is read-only: it never exposes a way to suspend a process, remove persistence, add
/// a firewall rule, or invoke any other response action. This is an authority-boundary invariant, so
/// it is enforced structurally, not only by the read-only annotations on each tool.
/// </summary>
public sealed class ResponseIsNotReachableFromMcpTests
{
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
}
