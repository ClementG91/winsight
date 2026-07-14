# WinSight MCP server

`winsight.exe mcp` lets an MCP-compatible AI client inspect WinSight's local,
read-only security observations. It is included in both installers and portable
archives starting with WinSight 0.7.0.

## Security boundary

The server uses MCP over standard input/output. The AI client starts one child
process for one session; WinSight does not open a port, bind to localhost, accept
remote clients or install a background MCP service.

All exposed tools are declared read-only, idempotent, non-destructive and
closed-world. MCP never exposes process termination, file deletion, quarantine,
registry editing, firewall mutation or WFP policy changes. VirusTotal and every
other network lookup are disabled inside MCP scans even when `WINSIGHT_VT_KEY` is
present in the parent environment.

Remember that the configured AI client may send tool results to its model provider.
That transfer is controlled by the AI client, not by WinSight. Review the client's
privacy policy and tool-confirmation UI before enabling evidence access.

## Configure a client

Point the MCP client's `command` at the installed executable. A common JSON shape is:

```json
{
  "mcpServers": {
    "winsight": {
      "command": "C:\\Users\\YOUR-NAME\\AppData\\Local\\Programs\\WinSight\\winsight.exe",
      "args": ["mcp"]
    }
  }
}
```

The exact settings filename and UI vary by MCP client. For a portable installation,
use the absolute path to the extracted `winsight.exe` with the `mcp` argument. Do not wrap the server in
PowerShell, `cmd.exe`, an HTTP relay or a network tunnel.

## Exposed tools

| Tool | Purpose | Default disclosure |
|---|---|---|
| `winsight_get_capabilities` | Lists scanners and active privacy controls without scanning. | Product metadata only. |
| `winsight_overview` | Runs the balanced seven-scanner overview. | Summaries/counts; noteworthy-only. |
| `winsight_scan` | Runs one named scanner, including large opt-in inventories. | Summaries/counts; noteworthy-only. |

The server also publishes `winsight://capabilities` and
`winsight://security-model` as MCP resources.

`includeEvidence=true` is required for item-level results. Evidence is capped at
200 items per report, user-profile paths are replaced with environment placeholders,
and command/command-line fields are omitted. Only one scan runs at a time and a scan
has a 90-second safety limit.

Raw sensitive fields require two independent choices:

1. The user starts the MCP server with `WINSIGHT_MCP_ALLOW_SENSITIVE=1`.
2. The individual call sets both `includeEvidence=true` and
   `includeSensitive=true`.

Do not enable this globally unless the selected AI client and model endpoint are
trusted to receive local paths and command lines.

## Protocol and compatibility

WinSight pins the [latest published stable MCP revision](https://modelcontextprotocol.io/specification/2025-11-25),
`2025-11-25`, through the [official C# MCP SDK](https://github.com/modelcontextprotocol/csharp-sdk).
Packaging and installer tests perform a real initialization,
list every tool, verify the read-only annotations and invoke the capability tool on
native x64 and Arm64 runners.

The MCP surface follows the same report semantics as the CLI and dashboard. A
`notable` item is evidence worth investigating, not proof of compromise and not a
claim that WinSight remediated anything.
