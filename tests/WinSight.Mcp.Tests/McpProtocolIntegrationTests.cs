using System.Diagnostics;
using System.Text.Json;
using Xunit;

namespace WinSight.Mcp.Tests;

public sealed class McpProtocolIntegrationTests
{
    /// <summary>Every posture a live read may legitimately report, and nothing else.</summary>
    private static readonly string[] PostureSummaries = ["Unavailable", "AuditOnly", "Active", "Degraded"];

    /// <summary>The prompts this server publishes, in the order the assertion sorts them into.</summary>
    private static readonly string[] ExpectedPrompts = ["winsight_explain_alert", "winsight_triage_machine"];

    /// <summary>
    /// Drives the real server over the real protocol, end to end.
    /// </summary>
    /// <remarks>
    /// The budget is generous on purpose. This is not a unit test with a mocked transport: it spawns
    /// the packaged server and makes it do genuine work, and one call — the absent-pid drill-down —
    /// takes a full process snapshot, measured at about four seconds on an idle desktop. It also
    /// runs while the rest of the solution's suites are running, several of which scan the same
    /// machine, so the wall-clock cost under contention is several times the isolated cost. A budget
    /// tight enough to fail there would be testing the runner's load, not the protocol.
    /// </remarks>
    [Fact(Timeout = 180000)]
    public async Task StdioServer_NegotiatesListsAndCallsReadOnlyTools()
    {
        var server = Path.Combine(AppContext.BaseDirectory, "winsight.dll");
        Assert.True(File.Exists(server), $"Missing MCP server at {server}");

        var dotnet = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet";
        var start = new ProcessStartInfo(dotnet)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add(server);
        start.ArgumentList.Add("mcp");

        using var process = Process.Start(start) ?? throw new InvalidOperationException("Unable to start MCP server.");
        try
        {
            await SendAsync(process, """
                {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"winsight-tests","version":"1.0"}}}
                """);
            using var initialized = await ReadAsync(process);
            Assert.Equal("2025-11-25", initialized.RootElement
                .GetProperty("result").GetProperty("protocolVersion").GetString());
            Assert.Equal("winsight", initialized.RootElement
                .GetProperty("result").GetProperty("serverInfo").GetProperty("name").GetString());

            await SendAsync(process, """{"jsonrpc":"2.0","method":"notifications/initialized"}""");
            await SendAsync(process, """{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}""");
            using var tools = await ReadAsync(process);
            var listedTools = tools.RootElement.GetProperty("result").GetProperty("tools").EnumerateArray().ToList();
            // The count is stated in README.md and docs/MCP.md, so the assertion names them: a tool
            // added without touching either leaves the project advertising a surface it no longer
            // has, which is the drift this suite already caught twice in the descriptions.
            Assert.True(
                listedTools.Count == 6,
                $"The server publishes {listedTools.Count} tools; README.md and docs/MCP.md say 6. "
                + "Update both and this assertion together.");
            Assert.All(listedTools, tool =>
            {
                var annotations = tool.GetProperty("annotations");
                Assert.True(annotations.GetProperty("readOnlyHint").GetBoolean());
                Assert.False(annotations.GetProperty("destructiveHint").GetBoolean());
                Assert.False(annotations.GetProperty("openWorldHint").GetBoolean());
            });

            // The valid scanners must travel in the schema, because that is what a model reads to
            // decide what it may ask for. They were once described in prose that listed ten of the
            // fifteen, which made five scanners reachable and undiscoverable.
            var scannerSchema = listedTools
                .Single(tool => tool.GetProperty("name").GetString() == "winsight_scan")
                .GetProperty("inputSchema").GetProperty("properties").GetProperty("scanner");
            var offered = scannerSchema.GetProperty("enum").EnumerateArray()
                .Select(value => value.GetString())
                .ToArray();
            Assert.Equal(
                WinSight.Application.Adapters.SnapshotCommands.Order(StringComparer.Ordinal),
                offered.Order(StringComparer.Ordinal));

            await SendAsync(process, """
                {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"winsight_get_capabilities","arguments":{}}}
                """);
            using var called = await ReadAsync(process);
            var structured = called.RootElement.GetProperty("result").GetProperty("structuredContent");
            Assert.True(structured.GetProperty("readOnly").GetBoolean());
            Assert.False(structured.GetProperty("networkListener").GetBoolean());
            Assert.False(structured.GetProperty("networkReputationLookups").GetBoolean());
            Assert.Equal(15, structured.GetProperty("scanners").GetArrayLength());

            await SendAsync(process, """
                {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"winsight_scan","arguments":{"scanner":"hosts"}}}
                """);
            using var scanned = await ReadAsync(process);
            var scanResult = scanned.RootElement.GetProperty("result").GetProperty("structuredContent");
            Assert.False(scanResult.GetProperty("evidenceIncluded").GetBoolean());
            var hostReport = scanResult.GetProperty("reports")[0];
            Assert.Equal("hosts", hostReport.GetProperty("tool").GetString());
            Assert.Equal(0, hostReport.GetProperty("returnedItemCount").GetInt32());
            Assert.Empty(hostReport.GetProperty("items").EnumerateArray());

            // The dedicated history tool must answer over the protocol and tag its report "alerts".
            // Summary mode returns counts only, so this holds whether or not the journal has entries.
            await SendAsync(process, """
                {"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"winsight_alerts","arguments":{}}}
                """);
            using var alerts = await ReadAsync(process);
            var alertsResult = alerts.RootElement.GetProperty("result").GetProperty("structuredContent");
            Assert.False(alertsResult.GetProperty("evidenceIncluded").GetBoolean());
            Assert.Equal("alerts", alertsResult.GetProperty("reports")[0].GetProperty("tool").GetString());

            // Posture must answer over the protocol on a machine with no firewall service installed,
            // which is every CI runner. The contract is that it answers honestly rather than failing:
            // "Unavailable" is a verdict about WinSight's ability to see, not about the machine.
            await SendAsync(process, """
                {"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"winsight_outbound_firewall","arguments":{}}}
                """);
            using var posture = await ReadAsync(process);
            var postureResult = posture.RootElement.GetProperty("result").GetProperty("structuredContent");
            Assert.False(postureResult.GetProperty("evidenceIncluded").GetBoolean());
            var postureReport = postureResult.GetProperty("reports")[0];
            Assert.Equal("outbound-firewall", postureReport.GetProperty("tool").GetString());
            Assert.Contains(postureReport.GetProperty("summary").GetString(), PostureSummaries);

            // A pid that cannot be running answers "not running" rather than describing an absent
            // process as one with nothing wrong. Chosen above the Windows pid range so the assertion
            // does not depend on what the runner happens to have started.
            await SendAsync(process, """
                {"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"winsight_process","arguments":{"pid":999999}}}
                """);
            using var absent = await ReadAsync(process);
            var absentReport = absent.RootElement.GetProperty("result")
                .GetProperty("structuredContent").GetProperty("reports")[0];
            Assert.Equal("process", absentReport.GetProperty("tool").GetString());
            Assert.Contains(
                "not running",
                absentReport.GetProperty("summary").GetString(),
                StringComparison.OrdinalIgnoreCase);

            // Zero is the System Idle Process, which has no image to inspect. Answering "not
            // running" about it would be a false statement, so the tool refuses instead.
            await SendAsync(process, """
                {"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"winsight_process","arguments":{"pid":0}}}
                """);
            using var refused = await ReadAsync(process);
            Assert.True(IsFailure(refused), "winsight_process accepted pid 0.");

            await SendAsync(process, """{"jsonrpc":"2.0","id":5,"method":"resources/list","params":{}}""");
            using var resources = await ReadAsync(process);
            var resourceCount = resources.RootElement
                .GetProperty("result").GetProperty("resources").GetArrayLength();
            Assert.True(
                resourceCount == 3,
                $"The server publishes {resourceCount} resources; README.md and docs/MCP.md say 3. "
                + "Update both and this assertion together.");

            await SendAsync(process, """
                {"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"winsight://security-model"}}
                """);
            using var security = await ReadAsync(process);
            var content = security.RootElement.GetProperty("result").GetProperty("contents")[0];
            Assert.Contains("no HTTP endpoint", content.GetProperty("text").GetString(), StringComparison.OrdinalIgnoreCase);

            // The verdict model exists to stop a client rendering "the signature was never checked"
            // as "unsigned", so that is what this asserts it actually says.
            await SendAsync(process, """
                {"jsonrpc":"2.0","id":11,"method":"resources/read","params":{"uri":"winsight://verdict-model"}}
                """);
            using var verdicts = await ReadAsync(process);
            var verdictText = verdicts.RootElement.GetProperty("result")
                .GetProperty("contents")[0].GetProperty("text").GetString();
            Assert.Contains("Never describe it as unsigned", verdictText, StringComparison.Ordinal);
            Assert.Contains("commandLineConcern", verdictText, StringComparison.Ordinal);

            await SendAsync(process, """{"jsonrpc":"2.0","id":12,"method":"prompts/list","params":{}}""");
            using var prompts = await ReadAsync(process);
            var promptNames = prompts.RootElement.GetProperty("result").GetProperty("prompts")
                .EnumerateArray()
                .Select(prompt => prompt.GetProperty("name").GetString() ?? string.Empty)
                .Order(StringComparer.Ordinal)
                .ToArray();
            Assert.Equal(ExpectedPrompts, promptNames);

            // The prompt has to arrive carrying the rule it exists for. An empty or generic body
            // would list in the client's menu and correct nothing.
            await SendAsync(process, """
                {"jsonrpc":"2.0","id":13,"method":"prompts/get","params":{"name":"winsight_explain_alert","arguments":{}}}
                """);
            using var explain = await ReadAsync(process);
            var promptText = explain.RootElement.GetProperty("result").GetProperty("messages")[0]
                .GetProperty("content").GetProperty("text").GetString();
            Assert.Contains("attribution needs Administrator", promptText, StringComparison.Ordinal);
        }
        finally
        {
            process.StandardInput.Close();
            if (!process.WaitForExit(5000))
            {
                process.Kill(entireProcessTree: true);
            }
        }
    }

    /// <summary>
    /// True when the server refused a call, by either route the specification allows: a JSON-RPC
    /// error, or a result flagged <c>isError</c>. Accepting only one would make the assertion pass
    /// for the wrong reason if the SDK changed which it uses.
    /// </summary>
    private static bool IsFailure(JsonDocument response) =>
        response.RootElement.TryGetProperty("error", out _)
        || (response.RootElement.TryGetProperty("result", out var result)
            && result.TryGetProperty("isError", out var isError)
            && isError.GetBoolean());

    private static async Task SendAsync(Process process, string message)
    {
        await process.StandardInput.WriteLineAsync(message.ReplaceLineEndings(string.Empty));
        await process.StandardInput.FlushAsync();
    }

    private static async Task<JsonDocument> ReadAsync(Process process)
    {
        // Per-response, and deliberately longer than the server's own 90-second scan limit. Sizing it
        // below that budget makes the client give up first, so a scan the server would have refused
        // with a clear message becomes an opaque client-side timeout instead — and on a loaded runner
        // that shows up as a flake rather than as the real answer. The packaged smoke test sizes the
        // same call the same way, for the same reason.
        var line = await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(100));
        if (line is null)
        {
            var error = await process.StandardError.ReadToEndAsync();
            throw new InvalidOperationException($"MCP server closed stdout. stderr: {error}");
        }
        return JsonDocument.Parse(line);
    }
}
