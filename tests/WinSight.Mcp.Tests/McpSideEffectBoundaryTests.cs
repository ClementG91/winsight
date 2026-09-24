using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

using WinSight.Core;

using Xunit;

namespace WinSight.Mcp.Tests;

/// <summary>
/// RA-06. <see cref="ResponseIsNotReachableFromMcpTests"/> proves that no <i>listed</i> response
/// mutator is reachable from MCP. A mutator added later, or a write made straight through the
/// framework or a P/Invoke, would pass it. These tests hold everything MCP reaches to a rule at the
/// point where the IL walk leaves WinSight: no mutating framework API, no WinSight write gateway, and
/// only native functions reviewed as read-only - except inside three reviewed owners whose side
/// effects are named below. Each detector has a canary that must trip it.
/// </summary>
/// <remarks>
/// What this is not: a proof about every future side effect. It does not see reflection with a
/// computed name, a delegate built outside the walk, native code calling back, or runtime values -
/// which is why the one runtime switch MCP relies on, <c>allowNetworkLookups: false</c>, is pinned by
/// its own contract below.
/// </remarks>
public sealed class McpSideEffectBoundaryTests
{
    /// <summary>
    /// Methods MCP reaches whose side effect is known and accepted, and which the strict walk does
    /// not enter. Adding one is a review decision, and its reason is part of the read-only claim.
    /// </summary>
    private static readonly Dictionary<string, string> ReviewedOwners = new(StringComparer.Ordinal)
    {
        ["WinSight.NetMonitor.ConnectionMonitor.RunNetstat"] =
            "starts netstat.exe (read-only) when the native tables fail, and kills only that child on timeout",
        ["WinSight.Core.VirusTotalClient.Lookup"] =
            "HTTPS GET of a hash to VirusTotal; statically reachable, never run from MCP (allowNetworkLookups: false)",
        ["WinSight.Core.VirusTotalQuotaLimiter.Save"] =
            "WinSight's own VirusTotal quota file; same gate as the lookup it meters",
    };

    /// <summary>Framework APIs that change the machine, its configuration or the network, by name.</summary>
    private static readonly Dictionary<string, string[]> MutatingFrameworkApis = new(StringComparer.Ordinal)
    {
        ["System.IO.File"] =
        [
            "WriteAllText", "WriteAllTextAsync", "WriteAllBytes", "WriteAllBytesAsync", "WriteAllLines",
            "WriteAllLinesAsync", "AppendAllText", "AppendAllTextAsync", "AppendAllLines", "AppendAllLinesAsync",
            "AppendAllBytes", "AppendAllBytesAsync", "AppendText", "Create", "CreateText", "CreateSymbolicLink",
            "Delete", "Move", "Copy", "Replace", "SetAttributes", "SetCreationTime", "SetCreationTimeUtc",
            "SetLastAccessTime", "SetLastAccessTimeUtc", "SetLastWriteTime", "SetLastWriteTimeUtc",
            "SetUnixFileMode", "Encrypt", "Decrypt", "Open", "OpenWrite", "OpenHandle",
        ],
        ["System.IO.Directory"] =
        [
            "CreateDirectory", "CreateSymbolicLink", "CreateTempSubdirectory", "Delete", "Move",
            "SetCreationTime", "SetCreationTimeUtc", "SetLastAccessTime", "SetLastAccessTimeUtc",
            "SetLastWriteTime", "SetLastWriteTimeUtc", "SetCurrentDirectory",
        ],
        ["System.IO.FileInfo"] =
        [
            "Delete", "MoveTo", "CopyTo", "Create", "CreateText", "AppendText", "Open", "OpenWrite",
            "Replace", "Encrypt", "Decrypt", "set_IsReadOnly",
        ],
        ["System.IO.DirectoryInfo"] = ["Create", "CreateSubdirectory", "Delete", "MoveTo"],
        ["System.IO.FileSystemInfo"] =
        [
            "Delete", "set_Attributes", "set_CreationTime", "set_CreationTimeUtc", "set_LastAccessTime",
            "set_LastAccessTimeUtc", "set_LastWriteTime", "set_LastWriteTimeUtc", "CreateAsSymbolicLink",
        ],
        ["System.IO.FileSystemAclExtensions"] = ["SetAccessControl", "Create", "CreateDirectory"],
        ["Microsoft.Win32.Registry"] = ["SetValue"],
        ["Microsoft.Win32.RegistryKey"] =
        [
            "SetValue", "DeleteValue", "DeleteSubKey", "DeleteSubKeyTree", "CreateSubKey", "SetAccessControl", "Flush",
        ],
        ["System.Diagnostics.Process"] = ["Start", "Kill"],
        ["System.ServiceProcess.ServiceController"] = ["Start", "Stop", "Pause", "Continue", "ExecuteCommand"],
        ["System.Environment"] = ["SetEnvironmentVariable", "set_CurrentDirectory"],
        ["System.Diagnostics.EventLog"] = ["WriteEntry", "WriteEvent", "CreateEventSource", "DeleteEventSource", "Delete", "Clear"],
        ["System.Net.Http.HttpMessageInvoker"] = ["Send", "SendAsync"],
        ["System.Net.Http.HttpClient"] =
        [
            "Send", "SendAsync", "GetAsync", "GetStringAsync", "GetByteArrayAsync", "GetStreamAsync",
            "PostAsync", "PutAsync", "PatchAsync", "DeleteAsync",
        ],
        ["System.Net.Sockets.Socket"] = ["Connect", "ConnectAsync", "SendTo", "SendToAsync"],
        ["System.Net.Sockets.TcpClient"] = ["Connect", "ConnectAsync"],
        ["System.Net.Sockets.UdpClient"] = ["Send", "SendAsync", "Connect"],
    };

    /// <summary>WinSight's own primitives that create, write, rename or delete files and ACLs.</summary>
    private static readonly Dictionary<string, string[]> WriteGateways = new(StringComparer.Ordinal)
    {
        ["WinSight.Core.AtomicFile"] = ["TryWrite", "TryDelete"],
        ["WinSight.Core.AutomaticFileAccess"] =
        [
            "TryEnsureDirectory", "TryApplyProtectedDirectoryDacl", "TryCreateNewFile", "TryCreateNewFileLease",
            "TryAppendFile", "TryWriteAtomic", "TryDeleteFile", "TryRenameRelative",
        ],
        ["WinSight.Core.AutomaticFileAccess+LocalPathLease"] = ["TryDelete", "TryRename"],
    };

    /// <summary>
    /// Native functions reviewed as read-only (or process-local) where MCP reaches them. A new one
    /// fails the boundary test until someone has looked at what it does and added it here.
    /// </summary>
    private static readonly Dictionary<string, string> ReviewedNatives = new(StringComparer.OrdinalIgnoreCase)
    {
        ["ntdll.dll!NtQuerySystemInformation"] = "query (code integrity)",
        ["ntdll.dll!NtCreateFile"] = "opens with FILE_OPEN on the read paths reached here; writes go through the gateways above",
        ["ntdll.dll!RtlNtStatusToDosError"] = "status conversion",
        ["kernel32.dll!DuplicateHandle"] = "duplicates WinSight's own read handle in its own process",
        ["kernel32.dll!GetCurrentProcess"] = "pseudo-handle",
        ["kernel32.dll!GetFileInformationByHandle"] = "query",
        ["kernel32.dll!LocalFree"] = "frees a buffer the API above allocated",
        ["advapi32.dll!GetKernelObjectSecurity"] = "query",
        ["advapi32.dll!GetSecurityInfo"] = "query (firewall pipe owner)",
        ["advapi32.dll!AccessCheck"] = "query against a duplicated token",
        ["advapi32.dll!DuplicateToken"] = "process-local impersonation copy for AccessCheck",
        ["advapi32.dll!GetTokenInformation"] = "query",
        ["advapi32.dll!OpenProcessToken"] = "query access to WinSight's own token",
        ["wintrust.dll!WinVerifyTrust"] = "signature verification, revocation off",
        ["wintrust.dll!CryptCATAdminAcquireContext2"] = "catalog lookup",
        ["wintrust.dll!CryptCATAdminCalcHashFromFileHandle2"] = "hash of an open handle",
        ["wintrust.dll!CryptCATAdminEnumCatalogFromHash"] = "catalog lookup",
        ["wintrust.dll!CryptCATAdminReleaseCatalogContext"] = "release",
        ["wintrust.dll!CryptCATAdminReleaseContext"] = "release",
        ["wintrust.dll!CryptCATCatalogInfoFromContext"] = "catalog lookup",
        ["iphlpapi.dll!GetExtendedTcpTable"] = "query",
        ["iphlpapi.dll!GetExtendedUdpTable"] = "query",
    };

    /// <summary>The tools MCP exports; a new one is a new surface to review.</summary>
    private static readonly string[] ReviewedTools =
    [
        "WinSight.Mcp.WinSightMcpTools.AlertsAsync",
        "WinSight.Mcp.WinSightMcpTools.GetCapabilities",
        "WinSight.Mcp.WinSightMcpTools.OutboundFirewallAsync",
        "WinSight.Mcp.WinSightMcpTools.OverviewAsync",
        "WinSight.Mcp.WinSightMcpTools.ProcessAsync",
        "WinSight.Mcp.WinSightMcpTools.ScanAsync",
    ];

    private static IlCallGraph StrictWalk(IEnumerable<MethodBase> roots) =>
        new IlCallGraph(McpRoots.WinSightAssemblies.Value, method => ReviewedOwners.ContainsKey(IlCallGraph.Describe(method)))
            .Walk(roots);

    /// <summary>Everything a walk reached that the boundary does not allow, with the path to it.</summary>
    private static List<string> Violations(IlCallGraph graph)
    {
        var violations = new List<string>();
        foreach (var (caller, target) in graph.ExternalCalls)
        {
            if (target.DeclaringType?.FullName is { } type
                && MutatingFrameworkApis.TryGetValue(type, out var names)
                && names.Contains(target.Name, StringComparer.Ordinal))
            {
                violations.Add($"framework write: {IlCallGraph.Describe(target)} <= {graph.PathTo(caller)}");
            }
        }
        foreach (var method in graph.Reached)
        {
            if (method.DeclaringType?.FullName is { } type
                && WriteGateways.TryGetValue(type, out var names)
                && names.Contains(method.Name, StringComparer.Ordinal))
            {
                violations.Add($"write gateway: {graph.PathTo(method)}");
            }
        }
        foreach (var native in graph.NativeCalls)
        {
            var key = NativeKey(native);
            if (!ReviewedNatives.ContainsKey(key))
            {
                violations.Add($"unreviewed native: {key} <= {graph.PathTo(native)}");
            }
        }
        return violations;
    }

    private static string NativeKey(MethodBase native)
    {
        var import = native.GetCustomAttribute<DllImportAttribute>();
        var library = (import?.Value ?? "?").ToLowerInvariant();
        if (!library.EndsWith(".dll", StringComparison.Ordinal))
        {
            library += ".dll";
        }
        return $"{library}!{import?.EntryPoint ?? native.Name}";
    }

    [Fact]
    public void OutsideTheReviewedOwnersNothingMcpReachesChangesTheMachine()
    {
        var graph = StrictWalk(McpRoots.AllMethodsOf(typeof(McpScanService).Assembly));

        Assert.Empty(graph.Unresolved);
        var violations = Violations(graph);
        Assert.True(violations.Count == 0, "MCP reaches a side effect outside the reviewed owners:\n" + string.Join("\n", violations));
    }

    /// <summary>
    /// The owners must still be reached, and still be where the side effect is: an owner renamed or
    /// no longer on MCP's path would otherwise sit in the list forever, excusing nothing.
    /// </summary>
    [Fact]
    public void TheReviewedOwnersAreStillWhereTheirSideEffectsAre()
    {
        var full = new IlCallGraph(McpRoots.WinSightAssemblies.Value).Walk(McpRoots.AllMethodsOf(typeof(McpScanService).Assembly));
        var reached = full.Reached.Select(IlCallGraph.Describe).ToHashSet(StringComparer.Ordinal);

        Assert.All(ReviewedOwners.Keys, owner => Assert.Contains(owner, reached));
        // Without the owners' exemption the same walk does find their side effects, so the strict
        // walk passes because of the review, not because the detectors are blind.
        var unexempted = Violations(full);
        Assert.Contains(unexempted, violation => violation.StartsWith("framework write: System.Diagnostics.Process.Start", StringComparison.Ordinal));
        Assert.Contains(unexempted, violation => violation.StartsWith("framework write: System.Net.Http.HttpMessageInvoker.Send", StringComparison.Ordinal));
        Assert.Contains(unexempted, violation => violation.StartsWith("write gateway:", StringComparison.Ordinal)
            && violation.Contains("VirusTotalQuotaLimiter.Save", StringComparison.Ordinal));
    }

    /// <summary>
    /// The VirusTotal owners are excused because MCP never runs them: every adapter call MCP makes
    /// passes <c>allowNetworkLookups: false</c>. That is a runtime value the IL walk cannot see, so
    /// the call sites are pinned here - an MCP call that omits it would default to lookups on.
    /// </summary>
    [Fact]
    public void EveryAdapterCallFromMcpTurnsNetworkLookupsOff()
    {
        var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        var sources = Directory.GetFiles(Path.Combine(root, "src", "WinSight.Mcp"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .ToDictionary(path => path, File.ReadAllText);
        var calls = 0;
        foreach (var (path, text) in sources)
        {
            foreach (Match call in Regex.Matches(text, @"Adapters\.(Run|RunOverview|Persistence|Connections)\("))
            {
                calls++;
                var arguments = ArgumentsFrom(text, call.Index + call.Length);
                Assert.True(arguments.Contains("allowNetworkLookups: false", StringComparison.Ordinal),
                    $"{Path.GetFileName(path)}: {call.Value} without allowNetworkLookups: false");
            }
        }
        Assert.True(calls >= 2, "the MCP adapter call sites were not found");
    }

    private static string ArgumentsFrom(string text, int start)
    {
        var depth = 1;
        for (var i = start; i < text.Length; i++)
        {
            depth += text[i] switch { '(' => 1, ')' => -1, _ => 0 };
            if (depth == 0)
            {
                return text[start..i];
            }
        }
        return text[start..];
    }

    [Fact]
    public void TheExportedToolsAreTheReviewedOnesAndAllDeclareReadOnly()
    {
        var tools = typeof(McpScanService).Assembly.GetTypes()
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            .Select(method => (Method: method, Attribute: method.GetCustomAttributes()
                .FirstOrDefault(attribute => attribute.GetType().Name == "McpServerToolAttribute")))
            .Where(tool => tool.Attribute is not null)
            .ToList();

        Assert.Equal(ReviewedTools, tools.Select(tool => IlCallGraph.Describe(tool.Method)).Order(StringComparer.Ordinal));
        Assert.All(tools, tool =>
        {
            var attribute = tool.Attribute!;
            Assert.Equal(true, attribute.GetType().GetProperty("ReadOnly")!.GetValue(attribute));
            Assert.Equal(false, attribute.GetType().GetProperty("Destructive")!.GetValue(attribute));
            Assert.Equal(false, attribute.GetType().GetProperty("OpenWorld")!.GetValue(attribute));
        });
    }

    /// <summary>Each detector trips on the change it exists to catch.</summary>
    [Theory]
    [InlineData(nameof(Canaries.WritesAFile), "framework write: System.IO.File.WriteAllText")]
    [InlineData(nameof(Canaries.SetsARegistryValue), "framework write: Microsoft.Win32.Registry.SetValue")]
    [InlineData(nameof(Canaries.StartsAProcess), "framework write: System.Diagnostics.Process.Start")]
    [InlineData(nameof(Canaries.CallsAnUnreviewedNativeFunction), "unreviewed native: kernel32.dll!DeleteFileW")]
    [InlineData(nameof(Canaries.ReachesAWriteGatewayThroughANewPath), "write gateway: ")]
    public void EachDetectorCatchesItsCanary(string canary, string expected)
    {
        var root = typeof(Canaries).GetMethod(canary, BindingFlags.Public | BindingFlags.Static)!;

        var violations = Violations(StrictWalk([root]));

        Assert.Contains(violations, violation => violation.StartsWith(expected, StringComparison.Ordinal));
    }

    /// <summary>
    /// The positive control on real code: the CLI, which offers the response verbs, writes files -
    /// and the detectors see it.
    /// </summary>
    [Fact]
    public void TheDetectorsSeeTheWritesTheCliMakes()
    {
        var cli = McpRoots.WinSightAssemblies.Value.Single(assembly => assembly.GetName().Name == "winsight");

        var violations = Violations(StrictWalk([cli.EntryPoint!]));

        Assert.Contains(violations, violation => violation.StartsWith("write gateway:", StringComparison.Ordinal)
            && violation.Contains("WinSight.Response.RuleStore", StringComparison.Ordinal));
    }

    /// <summary>
    /// Never executed, only walked: stand-ins for code a future change could put behind an MCP tool.
    /// </summary>
    internal static class Canaries
    {
        public static void WritesAFile(string path) => File.WriteAllText(path, "canary");

        public static void SetsARegistryValue() =>
            Microsoft.Win32.Registry.SetValue(@"HKEY_CURRENT_USER\Software\WinSightCanary", "Canary", 1);

        public static void StartsAProcess() => System.Diagnostics.Process.Start("cmd.exe")?.Dispose();

        public static bool CallsAnUnreviewedNativeFunction(string path) => DeleteFileW(path);

        public static bool ReachesAWriteGatewayThroughANewPath(string path) => Relay(path);

        private static bool Relay(string path) => AutomaticFileAccess.TryDeleteFile(path);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteFileW(string path);
    }
}
