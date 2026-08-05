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

    [McpServerResource(
        UriTemplate = "winsight://verdict-model",
        Name = "winsight-verdict-model",
        Title = "How to read a WinSight verdict",
        MimeType = "text/markdown")]
    [Description(
        "How to read a WinSight finding without overstating it: what a file-status verdict does and " +
        "does not establish, why a valid signature can still be notable, and which pairs of fields " +
        "must never be merged into one sentence.")]
    public static string GetVerdictModel() => McpCatalog.VerdictModel;
}
