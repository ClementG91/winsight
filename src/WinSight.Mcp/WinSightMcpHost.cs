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
        // Registered as the posture-only interface, so nothing resolved from this container can
        // reach the gateway's policy mutations even by accident.
        builder.Services.AddSingleton(_ => WinSight.Application.FirewallServiceAdapter.CreatePostureReader());
        builder.Services.AddSingleton<McpFirewallPostureService>();
        builder.Services
            .AddMcpServer(options =>
            {
                // Deliberately not pinned. The SDK negotiates every revision it implements, which is
                // what the specification asks of a server: a client declares its version per request
                // and the server accepts or rejects it, and clients MAY be on different revisions.
                //
                // Pinning it to 2026-07-28 makes the server unreachable rather than modern. That
                // revision removed the initialize handshake, so forcing it as the only offer answers
                // every handshake-based client with "Protocol version '2026-07-28' is not available
                // through the initialize handshake" - which is every client still on 2025-11-25 or
                // earlier. Leaving it unset keeps `server/discover` and per-request `_meta` for new
                // clients and the handshake for older ones.
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
            .WithResources<WinSightMcpResources>()
            .WithPrompts<WinSightMcpPrompts>();

        await builder.Build().RunAsync(cancellationToken).ConfigureAwait(false);
        return 0;
    }
}
