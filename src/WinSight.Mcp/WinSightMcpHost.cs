using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace WinSight.Mcp;

/// <summary>Creates the local stdio MCP host without writing non-protocol data to stdout.</summary>
public static class WinSightMcpHost
{
    public static async Task<int> RunAsync(CancellationToken cancellationToken = default)
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace);
        builder.Logging.SetMinimumLevel(LogLevel.Warning);

        var security = McpSecurityOptions.FromEnvironment();
        builder.Services.AddSingleton(security);
        builder.Services.AddSingleton<McpScanService>();
        builder.Services
            .AddMcpServer(options =>
            {
                options.ProtocolVersion = McpCatalog.ProtocolVersion;
                options.InitializationTimeout = TimeSpan.FromSeconds(15);
                options.ServerInfo = new Implementation
                {
                    Name = "winsight",
                    Title = "WinSight local security visibility",
                    Version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0",
                    Description = "Read-only local Windows security observations with privacy-bounded evidence.",
                    WebsiteUrl = "https://github.com/ClementG91/winsight",
                };
                options.ServerInstructions = McpCatalog.ServerInstructions;
            })
            .WithStdioServerTransport()
            .WithTools<WinSightMcpTools>()
            .WithResources<WinSightMcpResources>();

        await builder.Build().RunAsync(cancellationToken).ConfigureAwait(false);
        return 0;
    }
}
