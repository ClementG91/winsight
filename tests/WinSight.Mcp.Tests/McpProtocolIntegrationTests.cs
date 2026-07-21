using System.Diagnostics;
using System.Text.Json;
using Xunit;

namespace WinSight.Mcp.Tests;

public sealed class McpProtocolIntegrationTests
{
    [Fact(Timeout = 30000)]
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
            Assert.Equal(4, listedTools.Count);
            Assert.All(listedTools, tool =>
            {
                var annotations = tool.GetProperty("annotations");
                Assert.True(annotations.GetProperty("readOnlyHint").GetBoolean());
                Assert.False(annotations.GetProperty("destructiveHint").GetBoolean());
                Assert.False(annotations.GetProperty("openWorldHint").GetBoolean());
            });

            await SendAsync(process, """
                {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"winsight_get_capabilities","arguments":{}}}
                """);
            using var called = await ReadAsync(process);
            var structured = called.RootElement.GetProperty("result").GetProperty("structuredContent");
            Assert.True(structured.GetProperty("readOnly").GetBoolean());
            Assert.False(structured.GetProperty("networkListener").GetBoolean());
            Assert.False(structured.GetProperty("networkReputationLookups").GetBoolean());
            Assert.Equal(13, structured.GetProperty("scanners").GetArrayLength());

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

            await SendAsync(process, """{"jsonrpc":"2.0","id":5,"method":"resources/list","params":{}}""");
            using var resources = await ReadAsync(process);
            Assert.Equal(2, resources.RootElement.GetProperty("result").GetProperty("resources").GetArrayLength());

            await SendAsync(process, """
                {"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"winsight://security-model"}}
                """);
            using var security = await ReadAsync(process);
            var content = security.RootElement.GetProperty("result").GetProperty("contents")[0];
            Assert.Contains("no HTTP endpoint", content.GetProperty("text").GetString(), StringComparison.OrdinalIgnoreCase);
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

    private static async Task SendAsync(Process process, string message)
    {
        await process.StandardInput.WriteLineAsync(message.ReplaceLineEndings(string.Empty));
        await process.StandardInput.FlushAsync();
    }

    private static async Task<JsonDocument> ReadAsync(Process process)
    {
        var line = await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10));
        if (line is null)
        {
            var error = await process.StandardError.ReadToEndAsync();
            throw new InvalidOperationException($"MCP server closed stdout. stderr: {error}");
        }
        return JsonDocument.Parse(line);
    }
}
