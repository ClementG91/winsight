using System.ComponentModel;
using ModelContextProtocol.Server;

namespace WinSight.Mcp;

[McpServerResourceType]
public sealed class WinSightMcpResources(McpSecurityOptions security)
{
    [McpServerResource(
        UriTemplate = "winsight://capabilities",
        Name = "winsight-capabilities",
        Title = "WinSight capabilities",
        MimeType = "application/json")]
    [Description("Machine-readable WinSight scanner and privacy capability catalog.")]
    public string GetCapabilities() => McpCatalog.CapabilitiesJson(security.AllowSensitiveEvidence);

    [McpServerResource(
        UriTemplate = "winsight://security-model",
        Name = "winsight-security-model",
        Title = "WinSight MCP security model",
        MimeType = "text/markdown")]
    [Description("Read-only boundaries, privacy defaults and interpretation rules for WinSight MCP.")]
    public static string GetSecurityModel() => McpCatalog.SecurityModel;
}
